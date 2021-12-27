FROM docker.io/library/alpine:3.17
RUN apk --no-cache add ca-certificates
ADD ./eviction-webhook ./eviction-webhook
