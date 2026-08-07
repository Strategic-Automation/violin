FROM kalilinux/kali-rolling:latest

# Install Python 3, build dependencies, and pentest tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    git \
    curl \
    ca-certificates \
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

# Hermes sets $HOME to /root/.hermes/profiles/violin/home when running with -p violin.
# Guard script refs use $HOME/.hermes/profiles/violin/scripts/... which becomes nested.
# Create symlinks so the path resolves cleanly under all HOME configurations.
RUN mkdir -p /root/.hermes/profiles/violin/.hermes/profiles \
    && ln -sf /root/.hermes/profiles/violin /root/.hermes/profiles/violin/.hermes/profiles/violin \
    && mkdir -p /root/.hermes/profiles/violin/home/.hermes/profiles \
    && ln -sf /root/.hermes/profiles/violin /root/.hermes/profiles/violin/home/.hermes/profiles/violin

# Sync virtualenv dependencies
RUN uv sync --dev

# Ensure host engagements folder can be mounted
VOLUME ["/violin/engagements"]

# Default entrypoint
CMD ["uv", "run", "python", "-m", "benchmark.run"]
