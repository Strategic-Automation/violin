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
    seclists \
    wordlists \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python

# SecLists and the DIRB/params wordlists are referenced throughout the
# playbooks; without them every assessment falls back to a hand-built target
# wordlist, which is far weaker for content discovery (#222).
#
# Kali ships ProjectDiscovery httpx as `httpx-toolkit` to avoid colliding with
# the PyPI `httpx` client. That console script lands in /opt/hermes/bin, which
# precedes /usr/bin on PATH, so a bare `httpx` silently resolved to the wrong
# tool. Expose the security tool under the name the playbooks use; the Python
# client stays reachable as `python -m httpx`.
RUN mkdir -p /root/.local/bin && ln -sf /usr/bin/httpx-toolkit /root/.local/bin/httpx


# Install uv package manager & hermes-agent CLI + violin plugin deps.
# hermes-agent >=0.16 requires Python <3.14 and Kali rolling now ships 3.14,
# so system pip cannot resolve it — pin the CLI to an isolated uv-managed
# Python 3.13 environment instead of the distro python.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:/root/.cargo/bin:/opt/hermes/bin:${PATH}"
ENV HOME="/root"
RUN uv venv /opt/hermes --python 3.13 \
    && uv pip install --python /opt/hermes/bin/python \
        "hermes-agent>=0.18.0,<0.20" \
        duckduckgo-search \
        tirith \
        filelock \
        bashlex \
        netaddr \
        yarl



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
