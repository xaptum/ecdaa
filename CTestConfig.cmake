# The following options are automatically passed to the `memcheck` executable:
# `--error-exitcode=5` A memory error causes a return code of 5, so memory errors will fail the tests.
# `--leak-check=full` Search for memory leaks after program completion, and give a full report for each individually.
#   - As we're striving for "malloc-free" code, we expect to have zero memory leaks
# `-v` Verbose `memcheck` output
# `--track-origins=yes` Track the origin of uninitialized values (small Valgrind performance hit)
# `--partial-loads-ok=no` Loads from partially invalid addresses are treated the same as loads from completely invalid addresses

find_program(MEMORYCHECK_COMMAND NAMES valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "${MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=5 --leak-check=full -v --track-origins=yes --partial-loads-ok=no")
