FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/frp-cel-plugin /usr/local/bin/frp-cel-plugin
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/frp-cel-plugin"]
CMD ["-config", "/etc/frp-cel-plugin/config.yaml"]
