# GlassEQ Server

GlassEQ Server issues signed entitlements and controls access to official GlassEQ downloads. It does not process audio, profiles, device data, or diagnostics.

The project is under active development. The current service exposes liveness, database readiness, license activation, entitlement refresh, and license management endpoints. It issues entitlements with an AWS KMS Ed25519 key. Billing, recovery, and download endpoints are not implemented yet.

## Trust boundaries

- AWS KMS holds the entitlement private key. The service can request Ed25519 signatures but cannot export the private key.
- The Sparkle and Apple release keys do not belong to this service. The GlassEQ release workflow builds and signs updates separately.
- The ECS task role must not be able to upload, replace, or delete update artifacts.
- The ECS task security group must accept public HTTP traffic only through the Application Load Balancer. The load balancer must use its default `append` mode for `X-Forwarded-For`, with client-port preservation disabled. Activation rate limits use the rightmost address appended by the load balancer.
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
| `GLASSEQ_IDEMPOTENCY_KEY` | Unpadded Base64URL encoding of the 32-byte key that encrypts replay responses |
| `GLASSEQ_RATE_LIMIT_HMAC_KEY` | Unpadded Base64URL encoding of the 32-byte key that hashes client IP addresses |
| `GLASSEQ_HTTP_ADDRESS` | Listen address, defaults to `:8080` |

Keep the idempotency key stable across deployments so every task can replay responses created during the preceding 24 hours. Store both keys in the deployment's secret manager; do not commit them.

The KMS key must have key spec `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY`, and signing algorithm `ED25519_SHA_512`. The runtime AWS identity needs only `kms:GetPublicKey` and `kms:Sign` for that key.

The configured KMS key ID may be an alias. The server resolves it once at startup and uses the returned immutable key ARN for the process lifetime. Rotating the key requires a new JWS `kid` and replacement of the running tasks.

The service exposes:

- `GET /healthz` for process liveness.
- `GET /readyz` for PostgreSQL readiness.
- `POST /v1/activations` for creating or restoring one of a license's two activation slots.
- `POST /v1/entitlements/refresh` for replacing an activation's signed entitlement from current license state.
- `DELETE /v1/activations/current` for releasing the calling activation's slot.
- `POST /v1/management-sessions` for creating a 15-minute management session from a license key.
- `GET /v1/management/activations` for listing the license's active slots.
- `DELETE /v1/management/activations/{activation_id}` for releasing one of those slots.
- `POST /v1/management/license-key-rotations` for replacing the license key.

Successful activation responses remain replayable for 24 hours. Failed requests are evaluated again rather than cached. The service removes expired replay and rate-limit rows in bounded background batches.

Refresh and current-installation deactivation authenticate with the activation token returned during activation. Deactivation retains the token hash so repeating that operation returns 204, while other uses of the deactivated token fail.

Management sessions authenticate with the license key and return a short-lived bearer token. The service stores only its SHA-256 hash. Slot listing exposes opaque activation IDs and timestamps, not device details. Remote release is idempotent and cannot affect another license's activation.

License-key rotation requires a management session and an idempotency UUID. It returns the new key once, revokes the previous key, and leaves existing activations intact. The encrypted success response remains replayable for 24 hours so a lost HTTP response does not lose the new key.

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
