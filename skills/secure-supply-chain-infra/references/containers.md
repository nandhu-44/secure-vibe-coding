# Container hardening checklist

- [ ] Base image pinned by digest. Minimal (distroless, `-slim`, alpine, chainguard/wolfi).
- [ ] Multi-stage build. No compilers or package managers in the final image.
- [ ] `USER` non-root (numeric UID for K8s `runAsNonRoot`).
- [ ] No secrets in `ENV`, `ARG`, copied files, or layers. Use `RUN --mount=type=secret`.
- [ ] `.dockerignore` covers `.git`, `.env*`, `*.pem`, `node_modules`, test data.
- [ ] `HEALTHCHECK` defined. A single process per container.
- [ ] Run with `--read-only --cap-drop=ALL --security-opt=no-new-privileges` and a tmpfs for writable dirs.
- [ ] Never mount `/var/run/docker.sock` into app containers (that grants root on the host).
- [ ] Don't use `--privileged` or `--network=host` unless strictly necessary and documented.
- [ ] Scanned (Trivy/Grype), SBOM (syft), signed (cosign), and rebuilt regularly for patches.

## docker-compose
```yaml
services:
  db:
    image: postgres:17.2@sha256:<digest>
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    ports: ["127.0.0.1:5432:5432"]     # not 0.0.0.0
  app:
    build: .
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
secrets:
  db_password:
    file: ./secrets/db_password.txt     # gitignored
```
