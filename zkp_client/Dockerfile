FROM rust:latest
WORKDIR /zkp_client
EXPOSE 8888
COPY . .
RUN cargo install --path .
CMD ["zkp_client"]
