FROM rust:1.97-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --home /data shoal && mkdir -p /data && chown shoal:shoal /data
COPY --from=build /src/target/release/shoal /usr/local/bin/shoal
USER shoal
WORKDIR /data
ENV SHOAL_DB=/data/shoal.db
ENV SHOAL_BIND=0.0.0.0:7420
EXPOSE 7420
VOLUME ["/data"]
ENTRYPOINT ["shoal"]
