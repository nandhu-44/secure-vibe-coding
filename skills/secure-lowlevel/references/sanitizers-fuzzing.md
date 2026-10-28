# Sanitizers & fuzzing

## Sanitizer builds (tests/CI, not production)
```sh
clang -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all foo.c -o foo_asan
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./foo_asan < testcase
clang -g -O1 -fsanitize=memory -fsanitize-memory-track-origins foo.c   # uninitialized reads (all deps must be MSan-built)
clang -g -O1 -fsanitize=thread foo.c                                   # data races
```
Valgrind (`valgrind --leak-check=full --error-exitcode=1`) is the alternative when you can't recompile.

## libFuzzer harness (template)
```c
#include <stddef.h>
#include <stdint.h>
int parse_message(const uint8_t *data, size_t len, struct msg *out);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct msg m;
    (void)parse_message(data, size, &m);   /* must never crash, hang, or leak for any input */
    return 0;
}
```
```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined fuzz_parse.c parse.c -o fuzz_parse
./fuzz_parse -max_total_time=60 corpus/
```
Also: AFL++ (`afl-clang-fast`), `cargo fuzz` (Rust), `go test -fuzz=FuzzParse` (Go 1.18+), and OSS-Fuzz / ClusterFuzzLite for continuous fuzzing in CI.

## Static analysis
clang-tidy (`bugprone-*,cert-*,clang-analyzer-*`), `scan-build`, cppcheck, CodeQL (`cpp-security-extended`), Semgrep `p/c`, flawfinder (quick banned-API grep).
