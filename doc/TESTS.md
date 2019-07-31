# Running the ECDAA test and benchmark suites

## Tests

To run the test suite for a build in the `build` directory:
```bash
cd build
ctest -V
```

Running the integration tests requires `-DBUILD_EXAMPLES=ON`.

## Benchmarks

If the project is built with the CMake option `-DBUILD_BENCHMARKS=ON`,
a benchmark suite for each curve is built in the `benchmarksBin` directory.

## Testing TPM Support

If the project is built with the CMake option `-DECDAA_TPM_SUPPORT=ON`,
some of the tests will require a TPM 2.0 (or a simulator).

By default, the tests use a device-file-based TCTI,
using device file `/dev/tpm0`.
For this reason, `sudo` privileges may be required to run them.

The tests can instead be built to use a TCP-socket-based TCTI
(typically used by a [TPM 2.0 simulator](https://sourceforge.net/projects/ibmswtpm2/))
by using the CMake option `TEST_USE_TCP_TPM=ON`.

An ECDAA signing key must loaded in the TPM. The associated
public key (in x9.62 format) and TPM handle (as a hex integer) must be
in `build/test/tpm/pub_key.txt` and `build/test/tpm/handle.txt`, respectively.
Currently, only the `TPM_ECC_BN_P256` curve is supported in the tests.

### Convenience Scripts

If using a TPM 2.0 simulator for the tests,
convenience scripts in the `.travis` directory can be used to download and prepare the simulator:
```bash
./.travis/install-ibm-tpm2.sh ./ibm-tpm2-simulator
./.travis/run-ibm-tpm2.sh ./ibm-tpm2-simulator/
./.travis/prepare-tpm2.sh ./ibm-tpm2-simulator ./build/test/tpm
```

Note that the simulator requires OpenSSL libraries and header files to be available.

### Key Creation for a Physical TPM

If using a physical TPM for the tests, the required ECDAA signing key can
be created and loaded in the TPM using a test program in the `xaptum-tpm` project
if you built that project from source:
```bash
# Use the copy of the xaptum-tpm project
cd xaptum-tpm/build/testBin

# Run the key-creation program
./create_load_evict-test

# Copy the output files to the test directory
cp pub_key.txt ../../../test/tpm
cp handle.txt ../../../test/tpm
```

The tests will now be able to use this key.

NOTE: This program must only be run against a TPM on which you have Platform authorization,
and which holds no important data.
The preparation program runs `TPM2_Clear`!

## Code Analysis Tools

The continuous-integration build process also runs
multiple code analysis tools.

Test code coverage is measured using `gcov`, and monitored via `coveralls`.

### Valgrind

The Valgrind tool `memcheck` is used for heap memory checking.
Every build on `travis-ci` runs this test.

To run a `memcheck` test,
configure and build the project as explained in [BUILDING.md](BUILDING.md),
but also pass `-DCMAKE_BUILD_TYPE=RelWithDebInfo` to CMake during the configuration step.
(if using `ECDAA_TPM_SUPPORT=ON`, also prepare the TPM as explained [above](#testing-tpm-support)).
Then, in the build directory,
run the tests using the `memcheck` tool and display the results:
```bash
## (benchmarks and fuzzing are excluded because they take too long under the Valgrind instrumentation)
ctest -VV -E benchmark\|fuzz\|tool_test -T memcheck
../test/valgrind-tool-test.sh ./build > ./Testing/Temporary/MemoryChecker.ToolTest.log 2>&1

# Show the results
../.travis/show-memcheck-results.sh $(pwd)
```

### Scan-build

Clang's `scan-build` tool is a general static analyzer, run every build on `travis-ci`.

The `scan-build` tool can be run locally by doing the following
(if building dependencies from source, make sure to do that first):
```bash
./.travis/run-scanbuild.sh . ./build
```

### cppcheck

The `cppcheck` static analyzer is also available, and is run every build on `travis-ci`.
To run it do the following:

```bash
./.travis/run-cppcheck.sh . ./build
```

This tool is generally considered to have a lower false-positive rate than
many other static analyzers, though with that comes a potential loss of strictness.

### Address and Undefined Behavior Sanitizers

Google produced "sanitizer" tools (code instrumenters that check for errors
while running, and thus "dynamically") for checking memory use and
code that may produce undefined behavior.
These sanitizers are now part of both the Clang and GCC compilers.
The address sanitizer and undefined behavior sanitizer
(including the unsigned-int-overflow sanitizer) are run for every build on `travis-ci`.

To run tests using these sanitizers,
configure and build the project as explained in [BUILDING.md](BUILDING.md),
but also pass `-DCMAKE_BUILD_TYPE=RelWithSanitize` to CMake during the configuration step.
(if using `ECDAA_TPM_SUPPORT=ON`, also prepare the TPM as explained [above](#testing-tpm-support)).
Then, in the build directory,
run the tests (the instrumentation has been built into the executables):
```bash
## (benchmarks are excluded because they take too long under the sanitizer instrumentation)
ctest -VV -E benchmark
```

### Coverity

Coverity static analysis is run after any push to the `coverity_scan` branch.
Coverity is a static analyzer provided by Synopsys, and the reports
for this project can be found by clicking the Coverity link at the top of [README](../README.md).

