# syntax=docker/dockerfile:1.7
#
# Commit image for lsquic (LiteSpeed QUIC + HTTP/3). Small form on the org base.
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t lsquic .
# The checkout must include the git submodules (src/liblsquic/ls-qpack, src/lshpack).
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# BoringSSL: lsquic's required TLS library (README pins 0.20250807.0). Not packaged by Debian, so it is
# built once from the pinned release tarball into /opt/toolchains/deps (SPEC §6.2 item 19): static
# libssl.a/libcrypto.a, uninstrumented, -g -gdwarf-3. No network is needed by build.sh afterwards.
USER root
ARG BORINGSSL_VER=0.20250807.0
ARG BORINGSSL_SHA256=0cd3a2ba242ead4b3365b8c66cfed4a5f3f0ae511e9c0fd627edee1252d3dbe2
RUN d=/opt/toolchains/deps/boringssl-${BORINGSSL_VER} && mkdir -p "$d/src" "$d/lib" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz \
      https://github.com/google/boringssl/archive/refs/tags/${BORINGSSL_VER}.tar.gz \
 && echo "${BORINGSSL_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cmake -S "$d/src" -B /tmp/dep-build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-g -gdwarf-3" -DCMAKE_CXX_FLAGS="-g -gdwarf-3" -DBUILD_TESTING=OFF \
 && cmake --build /tmp/dep-build --target ssl crypto -j"$(nproc)" \
 && cp /tmp/dep-build/libssl.a /tmp/dep-build/libcrypto.a "$d/lib/" \
 && cp -r "$d/src/include" "$d/include" \
 && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX "$d"

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
