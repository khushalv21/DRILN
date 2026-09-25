# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL org.opencontainers.image.title="driln" \
      org.opencontainers.image.description="Intelligent automated pentesting engine"

# nmap is a system package (not downloadable via `driln setup`, which only
# fetches the Go-based ProjectDiscovery tools).
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user — `driln setup` installs tools to $HOME/.driln/bin,
# and there's no reason the scan engine needs root.
RUN useradd --create-home --shell /bin/bash driln
USER driln
WORKDIR /home/driln/app

ENV PATH="/home/driln/.local/bin:/home/driln/.driln/bin:${PATH}"

COPY --chown=driln:driln pyproject.toml README.md ./
COPY --chown=driln:driln driln ./driln

RUN pip install --user --no-cache-dir .

# Downloads subfinder/httpx/nuclei from GitHub releases into ~/.driln/bin.
# If this fails at build time (e.g. no network), the container still runs —
# `driln tools list` will just show them as missing until `driln setup` is
# re-run inside the container.
RUN driln setup || true

EXPOSE 8000

CMD ["driln", "serve", "--host", "0.0.0.0", "--port", "8000"]
