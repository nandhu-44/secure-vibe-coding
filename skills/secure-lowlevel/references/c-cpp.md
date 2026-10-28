# C / C++ digest (SEI CERT + CWE Top 25)

## Safe replacements
| Avoid | Use | Notes |
|---|---|---|
| `gets` | `fgets(buf, sizeof buf, stdin)` / `getline` | strip trailing `\n` |
| `strcpy`, `strcat` | `snprintf`, `strlcpy`/`strlcat`, `memcpy` after length check | `strlcpy` is in glibc ≥2.38 |
| `sprintf`, `vsprintf` | `snprintf`, `vsnprintf` | check `ret >= size` for truncation |
| `scanf("%s")` | `scanf("%63s")` / `fgets` + `sscanf` | width = size − 1 |
| `strncpy` | `strlcpy` / `snprintf("%s")` | `strncpy` may not NUL-terminate |
| `atoi`, `atol` | `strtol`/`strtoul` + errno + endptr + range | |
| `rand()` for secrets | `getrandom()`, `arc4random_buf`, `BCryptGenRandom` | |
| `tmpnam`, `mktemp` | `mkstemp`, `tmpfile` | |
| `system`, `popen` | `posix_spawn`, `execve` with argv | |
| `memset` to wipe secrets | `explicit_bzero`, `memset_s`, `OPENSSL_cleanse` | CWE-14 |
| `memcmp` on MACs | `CRYPTO_memcmp`, `sodium_memcmp` | constant time |
| `malloc(n * size)` | `calloc(n, size)`, `reallocarray`, checked mul | CWE-190 |
| `realloc(p, n)` assigned to `p` | `tmp = realloc(p, n); if (!tmp) {...} p = tmp;` | avoids a leak on failure |
| `alloca`, VLAs from input | fixed max or heap | stack exhaustion |
| `signal()` handlers with stdio | `sigaction` + `volatile sig_atomic_t` flag | |

## High-value CERT C rules
Rule identifiers and titles are quoted from the [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard) (Carnegie Mellon University). See the standard for full rules and exceptions.

- **ARR30-C** Do not form or use out-of-bounds pointers or array subscripts.
- **ARR38-C** Library functions must not form invalid pointers (size args correct).
- **STR31-C** Guarantee storage for strings has room for the data and the null terminator.
- **INT30-C / INT32-C** Unsigned wrap / signed overflow checks.
- **INT31-C** Integer conversions must not lose or misinterpret data.
- **MEM30-C** Do not access freed memory. **MEM31-C** Free dynamically allocated memory exactly once.
- **MEM35-C** Allocate sufficient memory for an object.
- **EXP33-C** Do not read uninitialized memory.
- **FIO30-C** Exclude user input from format strings.
- **FIO45-C** Avoid TOCTOU races while accessing files.
- **ENV33-C** Do not call `system()`.
- **MSC33-C** Do not pass invalid data to `asctime()`. **MSC41-C** Never hard-code sensitive information.
- **POS36-C** Observe correct revocation order while relinquishing privileges (setgid before setuid).

## C++ specifics
- RAII and smart pointers. `std::make_unique`. No owning raw pointers.
- `std::vector`/`std::string`/`std::array`/`std::span` instead of C arrays. `std::string_view` must not outlive its source.
- Iterator invalidation: don't hold iterators/references across `push_back`/`insert`/`erase`.
- Use `static_cast` (not C casts), `gsl::narrow` or a checked cast for narrowing.
- Exceptions: keep destructors `noexcept`. Use exception-safe resource handling.
- Enable libstdc++/libc++ hardening: `-D_GLIBCXX_ASSERTIONS` / `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST`.
- Follow C++ Core Guidelines (Lifetime, Bounds, Type profiles). Use clang-tidy checks `bugprone-*`, `cert-*`, `cppcoreguidelines-*`.
