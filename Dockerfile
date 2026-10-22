# Aegis scanner image.
#
# Multi-stage so the runtime layer carries only the wheel and the Trivy binary --
# the build toolchain never ships. Runs as a non-root user.
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir --upgrade pip build \
 && python -m build --wheel --outdir /dist


FROM python:3.12-slim AS runtime

ARG TRIVY_VERSION=0.76.1

# ca-certificates is needed to reach the CVE database over TLS; curl is used once,
# at build time, and removed in the same layer so it is not part of the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}" \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

RUN useradd --create-home --uid 10001 aegis \
 && mkdir -p /data /cache \
 && chown -R aegis:aegis /data /cache

USER aegis
WORKDIR /data

ENV AEGIS_DB=/data/aegis.db \
    AEGIS_OUTPUT_DIR=/data/reports \
    AEGIS_CACHE_DIR=/cache/trivy \
    TRIVY_CACHE_DIR=/cache/trivy

VOLUME ["/data", "/cache"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"

ENTRYPOINT ["aegis"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
