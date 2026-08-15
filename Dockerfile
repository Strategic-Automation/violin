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


# Install uv package manager & hermes-agent CLI + violin plugin deps
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:/root/.cargo/bin:${PATH}"
ENV HOME="/root"
RUN pip install --ignore-installed --break-system-packages \
    hermes-agent \
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

# Copy repo contents
COPY . /violin/

# Install the violin profile into Hermes per official distribution.yaml spec
RUN hermes profile install /violin --name violin -y

# Create home profile link so script paths resolve consistently under Hermes profile execution
RUN mkdir -p /root/.hermes/profiles/violin/home \
    && ln -sf /root/.hermes /root/.hermes/profiles/violin/home/.hermes

# Sync virtualenv dependencies
RUN uv sync --dev

# Ensure host engagements folder can be mounted
VOLUME ["/violin/engagements"]

# Reap orphaned subprocesses created by benchmark and guard executions.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default entrypoint
CMD ["uv", "run", "python", "-m", "benchmark.run"]
