# ELK Setup for ZYLAR

This directory contains the configuration to run a local Elasticsearch and Kibana instance using Docker Compose. Security has been disabled (`xpack.security.enabled=false`) for easier local development.

## Prerequisites
- Docker
- Docker Compose

## Starting the Stack
Navigate to this directory and run:

```bash
docker-compose up -d
```

Elasticsearch will be available at `http://localhost:9200`.
Kibana will be available at `http://localhost:5601`.

## Stopping the Stack
```bash
docker-compose down
```

To remove all retained data:
```bash
docker-compose down -v
```
