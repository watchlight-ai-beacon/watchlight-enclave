# Sandbox image for the example agent.
#
# The Watchlight SDK is installed at BUILD time on purpose: the sandbox runs
# with no network, so nothing can be fetched once it starts. Everything the
# agent needs has to be in the image.
FROM python:3.12-slim

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir watchlight

WORKDIR /work
