# Sandbox image for the example agent.
#
# The Watchlight SDK is installed at BUILD time on purpose: the sandbox runs
# with no network, so nothing can be fetched once it starts. Everything the
# agent needs has to be in the image.
#
# Versions are pinned. The evidence bundle records what the sandbox was
# constrained to; "whatever latest resolved to that morning" is not a statement
# anyone can audit later. In production, pin the base image by digest too
# (`python:3.12-slim@sha256:...`) so the image is reproducible byte for byte.
FROM python:3.12-slim

RUN pip install --no-cache-dir --upgrade "pip==25.3" \
 && pip install --no-cache-dir "watchlight==0.15.0"

WORKDIR /work

# Declared so the image is honest about what it needs, even though the driver
# forces a non-root uid regardless: an image that only works as root would
# fail confusingly rather than obviously. wl-enclave runs the sandbox as the
# invoking user, so the uid here is a floor, not the uid you will see.
USER 65532:65532
