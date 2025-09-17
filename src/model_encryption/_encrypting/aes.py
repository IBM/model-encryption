# Copyright 2025 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections.abc import Iterable
import concurrent.futures
import os
import pathlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from tqdm import tqdm


class AES256FileEncrypter:
    def __init__(self, encryption_key: pathlib.Path):
        """Inititlizes the AES256Encrypter."""
        with open(encryption_key, "rb") as f:
            self._key = f.read()
        if len(self._key) != 32:
            raise ValueError(
                f"Key is {len(self._key)} bytes long, expected 32 bytes."
            )

    def encrypt(
        self,
        model_path: pathlib.Path,
        *,
        file_patterns: Iterable[str] = frozenset(),
        remove_files: bool = True,
        use_progress_bar: bool = True,
    ) -> None:
        """Encrypt the files in a directory."""
        filenames_set = set()

        for file_pattern in file_patterns:
            filenames_set.update(list(model_path.glob("**/" + file_pattern)))

        # Filter-out all hidden files
        filenames = []
        for filename in filenames_set:
            fn = str(filename)
            if (
                not fn.startswith(".")
                and not fn.find("/.") >= 0
                and not os.path.isdir(fn)
            ):
                filenames.append(filename)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as tpe:
            chunk_size = int(1024 * 1024 / tpe._max_workers)
            futures = [
                tpe.submit(
                    self._encrypt_file,
                    filename,
                    pathlib.Path(str(filename) + ".enc"),
                    remove_files,
                    chunk_size=chunk_size,
                    position=i,
                    use_progress_bar=use_progress_bar,
                )
                for i, filename in enumerate(filenames)
            ]
            concurrent.futures.wait(futures)

    def _encrypt_file(
        self,
        input_file: pathlib.Path,
        output_file: pathlib.Path,
        remove_file: bool = True,
        chunk_size: int = 128 * 1024,
        position: int = 0,
        use_progress_bar: bool = True,
    ) -> None:
        """Encrypt a single file and remove the plain file if requested."""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self._key), modes.CFB(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        hash = hashes.SHA256()
        h = hmac.HMAC(self._key, hash, backend=default_backend())
        h.update(iv)

        file_size = os.path.getsize(input_file)

        progress = None
        if use_progress_bar:
            progress = tqdm(
                total=file_size,
                desc=f"Encrypting {os.path.basename(input_file)}",
                position=position,
                leave=True,
                unit="B",
                unit_scale=True,
            )

        with open(output_file, "wb") as fout:
            # will re-write hmac at the end
            fout.write(iv + b"\x00" * hash.digest_size)

            with open(input_file, "rb") as fin:
                while True:
                    data = fin.read(chunk_size)
                    if progress:
                        progress.update(len(data))
                    padded_data = padder.update(data)
                    encrypted_data = encryptor.update(padded_data)
                    h.update(encrypted_data)
                    fout.write(encrypted_data)
                    if len(data) < chunk_size:
                        break

            padded_data = padder.finalize()
            encrypted_data = (
                encryptor.update(padded_data) + encryptor.finalize()
            )
            h.update(encrypted_data)
            hmac_value = h.finalize()
            fout.write(encrypted_data)

            fout.seek(len(iv))
            fout.write(hmac_value)
            if progress:
                progress.close()

        if remove_file:
            os.remove(input_file)

    def decrypt(
        self,
        model_path: pathlib.Path,
        *,
        remove_files: bool = True,
        use_progress_bar: bool = True,
    ) -> None:
        """Decrypt all files ending in .enc and remove them if requested."""
        filenames = set()

        filenames.update(list(model_path.glob("**/*.enc")))

        exc = None

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as tpe:
            chunk_size = int(1024 * 1024 / tpe._max_workers)
            futures = [
                tpe.submit(
                    self._decrypt_file,
                    filename,
                    pathlib.Path(str(filename)[:-4]),
                    remove_files,
                    chunk_size=chunk_size,
                    position=i,
                    use_progress_bar=use_progress_bar,
                )
                for i, filename in enumerate(filenames)
            ]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    # Cancel all futures now
                    for f in futures:
                        f.cancel()
                    exc = e
        if exc:
            raise exc

    def _decrypt_file(
        self,
        input_file: pathlib.Path,
        output_file: pathlib.Path,
        remove_file: bool = True,
        chunk_size: int = 128 * 1024,
        position: int = 0,
        use_progress_bar: bool = True,
    ) -> None:
        """Decyrpt a single file and remove the encrypted file if requested."""
        h = hmac.HMAC(self._key, hashes.SHA256(), backend=default_backend())

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        file_size = os.path.getsize(input_file)

        progress = None
        if use_progress_bar:
            progress = tqdm(
                total=file_size,
                desc=f"Decrypting {os.path.basename(input_file)}",
                position=position,
                leave=True,
                unit="B",
                unit_scale=True,
            )

        with open(output_file, "wb") as fout:
            with open(input_file, "rb") as fin:
                iv = fin.read(16)
                cipher = Cipher(
                    algorithms.AES(self._key),
                    modes.CFB(iv),
                    backend=default_backend(),
                )
                decryptor = cipher.decryptor()
                h.update(iv)
                hmac_value = fin.read(32)

                if progress:
                    progress.update(48)

                while True:
                    encrypted_data = fin.read(chunk_size)
                    if progress:
                        progress.update(len(encrypted_data))
                    h.update(encrypted_data)
                    decrypted_data = decryptor.update(encrypted_data)
                    data = unpadder.update(decrypted_data)
                    fout.write(data)
                    if len(encrypted_data) < chunk_size:
                        break

            try:
                h.verify(hmac_value)
                decrypted_data = decryptor.finalize()
                data = unpadder.update(decrypted_data) + unpadder.finalize()
                fout.write(data)
            except Exception as e:
                # e.g., HMAC failed
                os.remove(output_file)
                raise e
            finally:
                if progress:
                    progress.close()

        if remove_file:
            os.remove(input_file)
