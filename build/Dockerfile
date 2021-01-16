FROM alpine:latest

# set labels for metadata
LABEL maintainer="Morven Cao<morvencao@gmail.com>" \
  name="pod-image-patcher" \
  description="A Kubernetes mutating webhook server that implements sidecar injection" \
  summary="A Kubernetes mutating webhook server that implements sidecar injection"

# set environment variables
ENV SIDECAR_INJECTOR=/usr/local/bin/pod-image-patcher \
  USER_UID=1001 \
  USER_NAME=sidecar-injector

# install sidecar-injector binary
COPY build/_output/bin/pod-image-patcher ${SIDECAR_INJECTOR}

# copy licenses
RUN mkdir /licenses
COPY LICENSE /licenses

# set entrypoint
ENTRYPOINT ["/usr/local/bin/pod-image-patcher"]

# switch to non-root user
USER ${USER_UID}
