FROM rust:latest
WORKDIR /zkp_server
EXPOSE 9999
COPY . .
RUN cargo install --path .
CMD ["zkp_server"]
