# Go: unsafe, cgo and low-level pitfalls

- `unsafe.Pointer` conversions follow the six valid patterns in the `unsafe` package docs. Never store a `uintptr` and convert it back later (GC may move or free the object).
- Use `unsafe.Slice`/`unsafe.String` (Go 1.17+/1.20+) instead of hand-built slice headers.
- cgo: Go pointers passed to C must not contain Go pointers (cgocheck). C memory is not GC'd, so `C.free` it (defer). Check lengths before `C.GoBytes`.
- Integer conversions: `int(uint64)` and `int32(x)` silently truncate. Check ranges when parsing lengths (`strconv.ParseUint(s, 10, 32)`).
- Slices: `b[i:j]` panics on bad bounds, which is a DoS on untrusted input. Validate first. `append` may alias the underlying array, so copy before sharing.
- Goroutine races: run tests with `go test -race`. Protect maps (concurrent map writes crash).
- Limit readers: `io.LimitReader`, `http.MaxBytesReader`. Watch decompression bombs (`gzip.NewReader` + limit).
- Run `govulncheck`, `gosec`, `staticcheck`, and `go test -fuzz`.
