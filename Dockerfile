FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# the system traceroute does the probing; it is the only system package needed
RUN apt-get update \
    && apt-get install -y --no-install-recommends traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . \
    && useradd --system --no-create-home --uid 10001 pathmap \
    && install -d -o pathmap /data

# The history lives in /data, a volume. UDP traceroute needs no privileges, so the container runs as an unprivileged
# user and can run with a read-only root filesystem and no capabilities.
USER pathmap
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["pathmap"]
CMD ["--help"]
