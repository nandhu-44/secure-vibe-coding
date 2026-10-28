# Compiler & linker hardening

Adapted from the [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) (CC BY 4.0). Consult it for each flag's rationale, compiler-version requirements, and performance notes.

## GCC / Clang (Linux)
```make
CFLAGS   += -O2 -Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough \
            -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion \
            -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS \
            -fstrict-flex-arrays=3 -fstack-clash-protection -fstack-protector-strong \
            -fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing -ftrivial-auto-var-init=zero \
            -fPIE
CFLAGS   += -fcf-protection=full          # x86_64
# CFLAGS += -mbranch-protection=standard  # aarch64
LDFLAGS  += -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--as-needed -Wl,--no-copy-dt-needed-entries
# shared libraries: -fPIC -shared instead of -fPIE/-pie
```
`_FORTIFY_SOURCE` needs optimization (`-O1`+). Check what you got with `checksec --file=./bin` or `readelf -lW`.

## CMake
```cmake
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(CheckPIESupported)
check_pie_supported()
add_compile_options(-Wall -Wextra -Wformat=2 -Werror=format-security -fstack-protector-strong -fstack-clash-protection
                    $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3> -D_GLIBCXX_ASSERTIONS)
add_link_options(-Wl,-z,relro,-z,now -Wl,-z,noexecstack)
```

## MSVC
`/W4 /sdl /GS /guard:cf /Qspectre /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT`, link with `/guard:cf`.

## Rust
Release profile: `overflow-checks = true` for security-sensitive crates, `panic = "abort"` where appropriate. Avoid `unsafe` unless necessary.

## Go
`go build -trimpath -buildmode=pie`. Use `CGO_ENABLED=0` when cgo isn't needed.
