# GlassEQ Server

GlassEQ Server issues signed entitlements and controls access to official GlassEQ downloads. It does not process audio, profiles, device data, or diagnostics.

The project is under active development. The current service exposes liveness and database-readiness endpoints, validates its AWS KMS Ed25519 key at startup, and contains the v1 database schema. Activation, billing, recovery, and download endpoints are not implemented yet.

## Trust boundaries

- AWS KMS holds the entitlement private key. The service can request Ed25519 signatures but cannot export the private key.
- The Sparkle and Apple release keys do not belong to this service. The GlassEQ release workflow builds and signs updates separately.
- The ECS task role must not be able to upload, replace, or delete update artifacts.
- Logs must not contain credentials, entitlement bodies, email addresses, Stripe payloads, or download authorization headers.

## Local database

Start PostgreSQL and apply the schema:

```sh
docker compose up -d postgres
docker compose run --rm migrate up
```

The migration container uses `juhokoskela/goose:v3.27.3`. Its image digest is pinned in `compose.yaml`.

To remove the local database and its volume:

```sh
docker compose down --volumes
```

## Configuration

The server requires these environment variables:

| Variable | Purpose |
| --- | --- |
| `GLASSEQ_DATABASE_URL` | PostgreSQL connection URL |
| `GLASSEQ_ENTITLEMENT_KMS_KEY_ID` | AWS KMS key ARN, alias, or ID |
| `GLASSEQ_ENTITLEMENT_SIGNING_KEY_ID` | Public JWS `kid`, such as `entitlement-2026-01` |
| `GLASSEQ_HTTP_ADDRESS` | Listen address, defaults to `:8080` |

The KMS key must have key spec `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY`, and signing algorithm `ED25519_SHA_512`. The runtime AWS identity needs only `kms:GetPublicKey` and `kms:Sign` for that key.

The configured KMS key ID may be an alias. The server resolves it once at startup and uses the returned immutable key ARN for the process lifetime. Rotating the key requires a new JWS `kid` and replacement of the running tasks.

The service exposes:

- `GET /healthz` for process liveness.
- `GET /readyz` for PostgreSQL readiness.

## Checks

```sh
go test -race ./...
go vet ./...
docker build --build-arg SOURCE_REVISION=development .
```

Database migrations run separately from the application. Production deployment should run the pinned Goose image as a one-shot task before replacing the ECS service.

Published images must set `SOURCE_REVISION` to the exact Git commit used for the build. The image records that revision in its OCI metadata and includes the AGPL license text.

## License

GlassEQ Server is licensed under `AGPL-3.0-or-later`. See `LICENSE`.
