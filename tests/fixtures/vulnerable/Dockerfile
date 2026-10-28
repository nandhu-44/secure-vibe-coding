FROM node:latest
# expect-above: SV-INF-001, SV-INF-002
ENV STRIPE_SECRET_KEY=sk_test_abcdefghijkl
# expect-above: SV-INF-003
RUN curl -fsSL https://get.example-installer.sh | bash
# expect-above: SV-INF-004
USER root
# expect-above: SV-INF-002
