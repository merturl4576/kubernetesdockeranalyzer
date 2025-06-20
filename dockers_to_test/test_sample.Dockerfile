FROM ubuntu:20.04
COPY ./src /app
USER appuser
HEALTHCHECK CMD curl --fail http://localhost || exit 1
