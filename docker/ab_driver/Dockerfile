# SecOpent A/B driver image (NAS isolated A/B only — NOT production).
# Reusable container that can drive the ReasoningLoop A/B harness:
#   - python 3.11 (project supports >=3.11)
#   - docker CLI (so the control arm's nuclei runs via the host dockersock)
#   - the repo installed in editable mode (importable helpers)
# Run with: --network host, dockersock + work-mounts + repo binds, .env.ab.
FROM python:3.11-slim

ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONUNBUFFERED=1

# docker CLI (static binary, no daemon in this container)
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    cp /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*; \
    docker --version

WORKDIR /repo
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e .
# pytest is imported by the A/B helper module at module level.
RUN pip install --no-cache-dir -q pytest
