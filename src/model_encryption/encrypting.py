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

import pathlib
import sys


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from model_encryption._encrypting.aes import AES256FileEncrypter


class Config:
    """Configuration to use when encrypting models."""

    def __init__(self):
        """Initializes the default configuration for encryption."""
        self._encrypter = None
        pass

    def encrypt(
        self,
        model_path: pathlib.Path,
        file_patterns: list[str],
        *,
        remove_files: bool = True,
        use_progress_bar: bool = True,
    ) -> None:
        self._encrypter.encrypt(
            model_path,
            file_patterns=file_patterns,
            remove_files=remove_files,
            use_progress_bar=use_progress_bar,
        )

    def use_aes256_encryption(self, encryption_key: pathlib.Path) -> Self:
        """Use AES256 for encryption."""
        self._encrypter = AES256FileEncrypter(encryption_key)
        return self

    def decrypt(
        self,
        model_path: pathlib.Path,
        *,
        remove_files: bool = True,
        use_progress_bar: bool = True,
    ) -> None:
        """Decrypt all files in the model_path directory."""
        self._encrypter.decrypt(
            model_path,
            remove_files=remove_files,
            use_progress_bar=use_progress_bar,
        )
