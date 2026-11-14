# Draco Insomnis for Docker: not an app of its own but an add-on for PHP containers.
#
#   A. Inside your image (two lines in your Dockerfile, any image built on the official PHP ones):
#        COPY --from=ghcr.io/fermatacordis-create/draco-insomnis:latest /draco /opt/draco
#        RUN sh /opt/draco/install-docker.sh
#
#   B. Without rebuilding: this image fills a volume once, your app mounts it at /opt/draco and adds
#      PHP_INI_SCAN_DIR=":/opt/draco/conf.d" (see docker-compose.example.yml).
#
# Build from the repository root after bin/build-server.sh:  docker build -f server/docker/Dockerfile .
FROM busybox:1.37

ARG DRACO_VERSION
LABEL org.opencontainers.image.title="Draco Insomnis" \
      org.opencontainers.image.description="Firewall add-on for PHP containers: loads before every PHP script" \
      org.opencontainers.image.source="https://github.com/fermatacordis-create/draco-insomnis" \
      org.opencontainers.image.licenses="GPL-2.0-or-later" \
      org.opencontainers.image.version="${DRACO_VERSION}"

COPY server/docker/build/draco /draco
# The volume mode: copy the files in, keep draco.ini and the evidence that are already there.
CMD ["sh", "/draco/fill-volume.sh", "/opt/draco"]
