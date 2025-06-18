# Running OTLS with Docker

This guide explains how to build and test the OTLS repository using Docker, without needing to install dependencies directly on your host machine.

## Prerequisites

- Docker
- Docker Compose

## Curve Selection

OTLS supports two different elliptic curves for cryptographic operations in the `com_conv` example:
- **BLS12-446** (default): A pairing-friendly curve suitable for advanced cryptographic protocols
- **Ed25519**: A widely-used curve optimized for performance and security

You can select the curve during the build process in several ways:

1. **Using environment variable**:
```bash
export RELIC_CURVE=Ed25519
docker compose build
```

2. **Using command line argument**:
```bash
docker compose build --build-arg RELIC_CURVE=Ed25519
```

3. **Using default (BLS12-446)**:
```bash
docker compose build
```

The build output will indicate which curve is being used. If an unknown curve is specified, the build will fail with a clear error message.

## Getting Started

1. Build the Docker image:

```bash
docker compose build
```

2. Run the Docker container in interactive mode:

```bash
docker compose up -d
docker compose exec otls bash
```

3. Once inside the container, you can run the tests:

```bash
# For local testing (both parties on same machine)
./run ./bin/[binaries] 12345 [more opts]

# For example
./run ./bin/example 12345 123 124
```
