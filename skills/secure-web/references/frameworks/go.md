# Go net/http secure baseline

```go
srv := &http.Server{
    Addr:              ":8443",
    Handler:           secureHeaders(http.MaxBytesHandler(mux, 1<<20)),
    ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
    WriteTimeout:      30 * time.Second, IdleTimeout: 60 * time.Second,
    TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
}

func secureHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        h := w.Header()
        h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        h.Set("X-Content-Type-Options", "nosniff")
        h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
        next.ServeHTTP(w, r)
    })
}

func (a *App) getInvoice(w http.ResponseWriter, r *http.Request) {
    user := userFromContext(r.Context())                // set by auth middleware
    id := r.PathValue("id")                             // Go 1.22+ mux patterns
    var inv Invoice
    err := a.db.QueryRowContext(r.Context(),
        "SELECT id, amount FROM invoices WHERE id = $1 AND account_id = $2", id, user.AccountID).Scan(&inv.ID, &inv.Amount)
    if errors.Is(err, sql.ErrNoRows) { http.NotFound(w, r); return }
    if err != nil { a.serverError(w, r, err); return }
    writeJSON(w, inv)
}
```

## Pitfalls
- `http.ListenAndServe` with no timeouts is vulnerable to Slowloris. Always build an `http.Server` with timeouts.
- `math/rand` is not for tokens. Use `crypto/rand` (`rand.Text()` in Go 1.24+, or `rand.Read`).
- `exec.Command("sh", "-c", userString)` is injection. Use `exec.Command("prog", arg1, arg2)`.
- `filepath.Join(base, userPath)` does not prevent `..`. Use `os.Root` (Go 1.24+) or clean and check the prefix.
- `html/template` (auto-escapes), not `text/template`, for HTML. `template.HTML(userInput)` disables escaping.
- `InsecureSkipVerify: true` is never acceptable in prod.
- Run `govulncheck ./...` in CI. Use `gosec` for static analysis.
