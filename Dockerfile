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
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python


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
COPY benchmark /violin/benchmark/

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

# The agent image contains the runner but not the golden inventory or evaluator.
RUN rm -rf /violin/benchmark/private \
    /violin/benchmark/targets/duck-store/calibration \
    /violin/benchmark/targets/duck-store/report.md \
    /violin/benchmark/proof.py \
    /violin/benchmark/score.py \
    /violin/benchmark/ai_judge.py \
    /violin/benchmark/indexer.py

# Ensure host engagements folder can be mounted
VOLUME ["/violin/engagements"]

# Reap orphaned subprocesses created by benchmark and guard executions.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default entrypoint
CMD ["uv", "run", "python", "-m", "benchmark.run"]
