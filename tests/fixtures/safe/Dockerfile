FROM python:3.13-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
RUN useradd --uid 10001 --create-home app
WORKDIR /app
COPY --chown=app:app . .
RUN --mount=type=secret,id=pip_token pip install --no-cache-dir -r requirements.txt
USER 10001
CMD ["python", "-m", "app"]
