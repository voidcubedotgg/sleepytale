FROM mcr.microsoft.com/devcontainers/java:3.0.11-25-trixie
USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        unzip \
        zip \
    && rm -rf /var/lib/apt/lists/*

USER vscode
