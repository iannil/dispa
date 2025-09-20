FROM rust:1.90 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/dispa ./dispa
COPY --from=builder /app/config ./config

RUN mkdir -p logs data && \
    chmod +x dispa

EXPOSE 8080 8081 9090

CMD ["./dispa", "-c", "config/config.toml"]