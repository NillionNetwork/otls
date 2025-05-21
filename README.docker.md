# Running OTLS with Docker

This guide explains how to build and test the OTLS repository using Docker, without needing to install dependencies directly on your host machine.

## Prerequisites

- Docker
- Docker Compose

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

## Testing with Two Containers

To simulate testing across two machines, you can run two separate containers:

1. Modify the docker-compose.yml file to include two services:

```yaml
version: '3'

services:
  otls1:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - ./:/opt/primus/otls
    ports:
      - "12345:12345"
    working_dir: /opt/primus/otls
    command: /bin/bash
    stdin_open: true
    tty: true
    networks:
      otls_network:
        ipv4_address: 172.28.0.2

  otls2:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - ./:/opt/primus/otls
    working_dir: /opt/primus/otls
    command: /bin/bash
    stdin_open: true
    tty: true
    networks:
      otls_network:
        ipv4_address: 172.28.0.3

networks:
  otls_network:
    ipam:
      driver: default
      config:
        - subnet: 172.28.0.0/16
```

2. Start both containers:

```bash
docker compose up -d
```

3. In one terminal, connect to the first container and run the first party:

```bash
docker compose exec otls1 bash
# Inside container
./bin/[binaries] 1 12345 [more opts]
```

4. In another terminal, connect to the second container and run the second party:

```bash
docker compose exec otls2 bash
# Inside container
./bin/[binaries] 2 12345 [more opts]
```

## Custom Tests

You can modify the Dockerfile or use the volume mount to make changes to the code and recompile:

```bash
# Inside the container
# Recompile after making changes
bash ./compile.sh /opt/primus/primus-emp
``` 