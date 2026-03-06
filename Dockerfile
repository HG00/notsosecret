FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/zeek/bin:${PATH}"

# Add Zeek OBS repository for Ubuntu 24.04
RUN apt-get update -qq && apt-get install -y --no-install-recommends curl gpg ca-certificates && \
    curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg && \
    echo "deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" \
        > /etc/apt/sources.list.d/zeek.list

# Install runtime dependencies
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        zeek nginx certbot python3-venv asciinema \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
WORKDIR /demo
COPY . /demo/

# Set up Python venv and install dependencies
RUN python3 -m venv /demo/venv && /demo/venv/bin/pip install --quiet --upgrade pip rich

ENTRYPOINT ["/demo/entrypoint.sh"]
