# iam-proxy-italia-wallet-instance-demo

Demo wallet instance for the [IAM Proxy Italia](https://github.com/italia/iam-proxy-italia) ecosystem. It obtains attestations from a Credential Issuer and presents them to a Relying Party. The application is aligned with the [IT-Wallet specifications 1.4.7](https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/).

This product is for testing and learning. Do not use it in production.

## What it does

- Obtain and hold the attestations published by the configured issuer, including PID and mDL.
- Present a held attestation to a Relying Party.
- Read revocation from the Status List carried in the attestation.
- Keep a local history of presentations on the Presentations Dashboard.

Held attestations stay in memory. Restarting the process clears them.

## Specifications

The application is Python 3.12 and Flask. Credential handling uses [pyeudiw](https://github.com/italia/eudi-wallet-it-python).

- [IT-Wallet Technical Documentation 1.4.7](https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/)
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)

## Configuration

Runtime settings are the YAML files in `config/`. That directory is local and is not stored in this repository. Keys and environment variables are described in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

The access password is `WALLET_INSTANCE_PASSWORD`.

## Run with IAM Proxy Italia

The full demo is the `wallet-instance-demo` service of IAM Proxy Italia. It is available at `https://demo-wi.example.org:8080`. The image is `ghcr.io/italia/iam-proxy-italia-wallet-instance-demo:v1.0`. Compose builds this Dockerfile when that tag is absent. In that compose file the password defaults to `wallet`.

## Run this repository

### Poetry

```bash
poetry install
```

Point `CONFIG_DIR` at a directory that contains `app_config.yaml`, export the variables listed in the configuration guide, then start the application.

```bash
poetry run python run.py
```

Without `WALLET_TLS_CERT` and `WALLET_TLS_KEY` the server speaks HTTP on port 8080.

### Docker Compose

```bash
docker compose up --build
```

The service reads `./config` and publishes port 8080.

Publishing a GitHub Release builds this Dockerfile and pushes `ghcr.io/italia/iam-proxy-italia-wallet-instance-demo` with the release tag.

## Use

1. Open the wallet and enter the demo password.
2. On Emissione, choose an attestation and obtain it.
3. On Presentazione, scan the Relying Party QR code.
4. On Dashboard Presentazioni, read the outcome and the Relying Party metadata of each presentation.

## Checks

```bash
make install-check-deps
npm ci
make check
```

`make check` runs the same lint, complexity, security, and frontend checks as CI.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

UI icons come from [Bootstrap Icons](https://icons.getbootstrap.com/) (MIT), in line with [Bootstrap Italia](https://italia.github.io/bootstrap-italia/). Asset licenses are listed in [docs/ASSETS.md](docs/ASSETS.md).
