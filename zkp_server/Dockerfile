FROM rust:latest
WORKDIR /zkp_server
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
      protobuf-compiler
EXPOSE 9999
COPY . .
RUN cargo install --path .
CMD ["zkp_server"]
