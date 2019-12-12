# ecdaa

[![Release](https://img.shields.io/github/release/xaptum/ecdaa.svg)](https://github.com/xaptum/ecdaa/releases)
[![Build Status](https://travis-ci.org/xaptum/ecdaa.svg?branch=master)](https://travis-ci.org/xaptum/ecdaa)
[![Coverage Status](https://coveralls.io/repos/github/xaptum/ecdaa/badge.svg?branch=master)](https://coveralls.io/github/xaptum/ecdaa?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13775/badge.svg)](https://scan.coverity.com/projects/xaptum-ecdaa)

A C implementation of elliptic-curve-based [Direct Anonymous Attestation signatures](https://en.wikipedia.org/wiki/Direct_Anonymous_Attestation),
using the LRSW-DAA scheme.

The project provides all DAA functionality for Issuers, Members, and Verifiers.
Pseudonym linking ("basename signatures") is optional, and secret-key revocation lists can be used.

The algorithm used is compatible with Version 1.1 Release Draft of the
[FIDO ECDAA](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-ecdaa-algorithm-v1.1-id-20170202.html)
specification.
Further implementation details can be found in [doc/IMPLEMENTATION.md](doc/IMPLEMENTATION.md).

## Installation

See [doc/BUILDING.md](doc/BUILDING.md) for more information on building from source.

Packages are also available for the following distributions.

### Debian (Jessie or Stretch)

``` bash
# Install the Xaptum APT repo GPG signing key.
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca

# Add the repository to your APT sources, replacing <dist> with either jessie or stretch.
echo "deb http://dl.bintray.com/xaptum/deb <dist> main" | sudo tee /etc/apt/sources.list.d/xaptum.list

# Update APT
sudo apt-get update

# Install the CLI tool and shared library
sudo apt-get install ecdaa

# For developers, header files and shared libraries can also be installed
sudo apt-get install libecdaa-dev

# For using a TPM 2.0, install the ecdaa-tpm library (and, optionally, development package)
sudo apt-get install libecdaa-tpm0
sudo apt-get install libecdaa-tpm-dev

```

### Homebrew (MacOS)

``` bash
# Tap the Xaptum Homebrew repository.
brew tap xaptum/xaptum

# Install the library.
brew install xaptum
```

## Usage

Information on using the library can be found in the [doc/USAGE.md](doc/USAGE.md) document.

The `ecdaa` command-line tool provides a simple, file-based interface for all DAA functionality.
If building from source, it's available in the `tool` directory.

A basic Join-Sign-Verify flow is shown below.

### Create Group

```bash
# Issuer creates a new keypair
ecdaa issuer genkeys -p issuer_public.bin -s issuer_private.bin
```

`...Issuer distributes issuer_public.bin to any Verifiers...`

```bash
# Verifier extracts group public key from Issuer's public key
ecdaa extractgpk -p issuer_public.bin -g group_public.bin
```

`...Verifier saves group_public.bin...`

### Join

```bash
# Member creates a keypair
ecdaa member genkeys -p member_public.bin -s member_private.bin
```

`...Member sends member_public.bin to Issuer...`

```bash
# Issuer creates a credential on that public key
ecdaa issuer issuecredential -p member_public.bin -s issuer_private.bin -c member_credential.bin
```

`...Issuer sends member_credential.bin to Member...`

`...Member saves the member_credential.bin and its member_private.bin...`

### Sign

`...Member creates a message to be signed in the file message.bin...`

```bash
# Member creates signature over the message
ecdaa member sign -s member_private.bin -c member_credential.bin -m message.bin -g signature.bin
```

`...Member sends message.bin and signature.bin to Verifier...`

### Verify 

```bash
# Verifier checks signature
ecdaa verify -g group_public.bin -m message.bin -s signature.bin
```

## License
Copyright 2017-2019 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
