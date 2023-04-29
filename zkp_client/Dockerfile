FROM rust:latest
WORKDIR /zkp_client
ENV DOCKER_MODE=
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
      protobuf-compiler
EXPOSE 8888
COPY . .
RUN cargo install --path .
CMD ["zkp_client"]

