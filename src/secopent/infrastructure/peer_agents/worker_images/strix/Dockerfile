# secopent peer-worker: strix (version-pinned). Digest is recorded in
# PEER_IMAGE_CATALOG after build/pull (supply-chain policy §8.1).
FROM python:3.12-slim

RUN pip install --no-cache-dir strix-agent==1.4.1

COPY entrypoint.py /opt/entrypoint.py

# non-root where possible; strix's own sandbox runs nested containers via the
# mounted docker socket (peer-worker profile, see ADR peer-worker-profile).
USER 65532:65532
WORKDIR /exchange

ENTRYPOINT ["python", "/opt/entrypoint.py"]
