FROM kalilinux/kali-rolling:latest

# Install Python 3, build dependencies, and pentest tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    git \
    curl \
    ca-certificates \
    tini \
    dnsutils \
    jq \
    nmap \
    gobuster \
    sqlmap \
    nikto \
    hydra \
    ffuf \
    whatweb \
    wafw00f \
    exploitdb \
    nuclei \
    httpx-toolkit \
    dnsx \
    subfinder \
    wordlists \
    dirb \
    nodejs \
    npm \
    ripgrep \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python

# The small wordlists and DIRB packages provide candidate lists for discovery;
# the much larger SecLists archive is optional, not baked into the benchmark
# image. Playbooks must check which paths actually exist before use (#222).
#
# Kali ships ProjectDiscovery httpx as `httpx-toolkit` to avoid colliding with
# the PyPI `httpx` client. That console script lands in /opt/hermes/bin, which
# precedes /usr/bin on PATH, so a bare `httpx` silently resolved to the wrong
# tool. Expose the security tool under the name the playbooks use; the Python
# client stays reachable as `python -m httpx`.
RUN mkdir -p /root/.local/bin && ln -sf /usr/bin/httpx-toolkit /root/.local/bin/httpx


# Install uv and pinned Hermes v0.21.5 into a Python 3.13 environment.
# The upstream project declares requires-python >=3.11,<3.14; keep the CLI
# runtime inside that supported range and install the immutable audited source.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:/root/.cargo/bin:/opt/hermes/bin:${PATH}"
ENV HOME="/root"
ARG HERMES_TAG=v2026.9.24
ARG HERMES_COMMIT=f97608f178d1ffeca59860195ab7da295f7c8e5f
RUN git clone --depth 1 --branch "$HERMES_TAG" https://github.com/NousResearch/hermes-agent.git /opt/hermes-agent \
    && test "$(git -C /opt/hermes-agent rev-parse HEAD)" = "$HERMES_COMMIT" \
    && uv venv /opt/hermes --python 3.13 \
    && uv pip install --python /opt/hermes/bin/python \
        --editable /opt/hermes-agent \
        duckduckgo-search \
        tirith \
        filelock \
        bashlex \
        netaddr \
        yarl

# Browser tooling. The `browser` toolset drives the agent-browser CLI, which
# is an npm package with its own Chromium download -- neither comes with
# hermes-agent. Without this step the toolset is enabled but every call fails,
# so install it here rather than leaving agents to rediscover it (#223).
# No credentials are written into the image; anything needing a key is passed
# at runtime via -e.
RUN npm install -g agent-browser \
    && agent-browser install --with-deps \
    && npm cache clean --force



# Set up working directory
WORKDIR /violin

# Copy pyproject.toml and lock files first for efficient caching
COPY pyproject.toml uv.lock /violin/

# Copy only the runtime surface (whitelist). Dev-only paths (tests/, docs/,
# .github/, AGENTS.md, .kilo/, .codex/) are never built into the image.
COPY distribution.yaml config.yaml SOUL.md .hermes.md /violin/
COPY README.md LICENSE CHANGELOG.md CONTRIBUTING.md SECURITY.md /violin/
COPY plugins /violin/plugins/
COPY skills /violin/skills/
COPY scripts /violin/scripts/
COPY assets /violin/assets/
COPY benchmark/run.py /violin/benchmark/run.py
COPY benchmark/targets/duck-store/scope.yaml benchmark/targets/duck-store/engage.md /violin/benchmark/targets/duck-store/

# The image has no tests/ tree (whitelist above), so pytest must not be
# advertised as the workspace verify command. Hermes' project detection
# reads [tool.pytest.ini_options] from pyproject.toml and injects
# "Verify: pytest" into the agent's system prompt — a suite that cannot
# exist here, which agents chased at closeout instead of finalizing
# findings. Strip the (dev-only) pytest block from the baked copy.
RUN sed -i '/^\[tool\.pytest\.ini_options\]/,$d' /violin/pyproject.toml \
    && ! grep -q 'tool\.pytest' /violin/pyproject.toml

# Install the violin profile into Hermes per official distribution.yaml spec
RUN hermes profile install /violin --name violin -y

# Create home profile link so script paths resolve consistently under Hermes profile execution
RUN mkdir -p /root/.hermes/profiles/violin/home \
    && ln -sf /root/.hermes /root/.hermes/profiles/violin/home/.hermes

# Sync runtime dependencies only. Dev deps (pytest, ruff) are excluded so the
# agent image carries no test framework and no test suite — a pentest agent
# has no verify loop to run at closeout.
RUN uv sync --no-dev

# Ensure host engagements folder can be mounted
VOLUME ["/violin/engagements"]

# Reap orphaned subprocesses created by benchmark and guard executions.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default entrypoint
CMD ["uv", "run", "--no-dev", "python", "-m", "benchmark.run"]
