# Copyright 2025 The Sigstore Authors
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
#
# Modified for model_encryption by:
# - Stefan Berger <stefanb@linux.ibm.com>
#


"""The entry-point for `python -m model_encryption`.

This makes the project executable and allows using this invocation as CLI.
"""

if __name__ == "__main__":
    from model_encryption._cli import main

    main()
