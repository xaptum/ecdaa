# Building ECDAA from source

## Build Dependencies

* CMake (version 3.0 or higher)
* Python3 (for file generation during build)
* A C99-compliant compiler

* [AMCL](https://github.com/xaptum/amcl) (version 4.7)
  * Built with the support for the necessary curves
  * This library provides the pairing-based cryptography primitives
* [xaptum-tpm](https://github.com/xaptum/xaptum-tpm) (version 0.5.0 or higher)
  * Only required if building ECDAA with TPM support
  * This library provides a minimal interface to a TPM 2.0 chip

## Pairing-friendly Curves

The pairing-friendly curves used in the library are decided at build time.
For these instructions, the `ECDAA_CURVES` variable stands for
a comma-separated list of the curves to use.

The available curves are:
- 'BN254'
- 'BN254CX'
- 'BLS383'
- 'FP256BN'
  - Must be included if building with TPM 2.0 support

## Building

```bash
# Create a subdirectory to hold the build
mkdir -p build
cd build
```

### Building the dependencies from source (optional)

You can build the dependencies from source, rather than using packages.

Note: these steps only build the dependencies as shared libraries.
To build static libraries, or to use any other specific build options,
refer to the relevant repositories.

```bash
# Create a local installation location, and make CMake aware of it
mkdir -p ./deps
export CMAKE_PREFIX_PATH=$(pwd)/deps

# Build the AMCL library
../.travis/install-amcl.sh ./amcl ./deps ${ECDAA_CURVES}

# Build the xaptum-tpm library (if building with TPM support)
../.travis/install-xaptum-tpm.sh ./xaptum-tpm ./deps
```

### Building the ECDAA libraries and CLI tool

```bash
# Configure the build (Don't include the TEST_USE_TCP_TPM if testing against a physical TPM)
cmake .. -DCMAKE_BUILD_TYPE=Release -DECDAA_CURVES=${ECDAA_CURVES} -DTEST_USE_TCP_TPM=ON

# Build the library
cmake --build .
```

## Tests

Note: If a TPM 2.0 or a simulator is not available, the CMake option
`ECDAA_TPM_SUPPORT` must be set to `OFF` in the build configuration step above
for all tests to pass.

```bash
# Run the test suite
ctest -V
```

For information on the available tests and benchmarks, see [TESTS.md](TESTS.md).

## Installing

```bash
cd build
cmake --build . --target install
```

Configuration `.pc` files for `pkg-config` are also installed,
as well as an `ecdaa-config.cmake` file for configuration using CMake.

## CMake Options

The following CMake configuration options are supported.

| Option                              | Values          | Default    | Description                                              |
|-------------------------------------|-----------------|------------|----------------------------------------------------------|
| ECDAA_CURVES                        | see above       | FP256BN    | Pairing-friendly curve(s) to use                         |
| ECDAA_TPM_SUPPORT                   | ON, OFF         | ON         | Build with support for using a TPM2.0                    |
| CMAKE_BUILD_TYPE                    | Release         |            | With full optimizations.                                 |
|                                     | Debug           |            | With debug symbols.                                      |
|                                     | RelWithDebInfo  |            | With full optimizations and debug symbols.               |
|                                     | RelWithSanitize |            | With address and undefined-behavior sanitizers.          |
|                                     | Dev             |            | With full optimizations and warnings treated as errors   |
|                                     | DevDebug        |            | With debug symbols and warnings treated as errors        |
| CMAKE_INSTALL_PREFIX                | <string>        | /usr/local | The directory to install the library in.                 |
| BUILD_BENCHMARKS                    | ON, OFF         | ON         | Build benchmark programs                                 |
| BUILD_EXAMPLES                      | ON, OFF         | OFF        | Build example programs                                   |
| BUILD_TOOL                          | ON, OFF         | ON         | Build benchmark programs                                 |
| BUILD_SHARED_LIBS                   | ON, OFF         | ON         | Build shared libraries.                                  |
| BUILD_STATIC_LIBS                   | ON, OFF         | OFF        | Build static libraries.                                  |
| BUILD_TESTING                       | ON, OFF         | ON         | Build the test suite.                                    |
| STATIC_SUFFIX                       | <string>        | <none>     | Appends a suffix to the static lib name.                 |
| TEST_USE_TCP_TPM                    | ON, OFF         | OFF        | Use a TCP socket TCTI for the TPM tests.                 |
