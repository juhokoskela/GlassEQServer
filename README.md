# GlassEQ Server

GlassEQ Server issues signed entitlements and controls access to official GlassEQ downloads. It does not process audio, profiles, device data, or diagnostics.

The project is under active development. The service exposes liveness, database readiness, license activation, entitlement refresh, license management, and email recovery. When Stripe is configured, a signed webhook fulfills purchases from the two configured Payment Links and reconciles monthly renewals, payment recovery, and cancellation. GlassEQ sends license keys and recovery tokens through Amazon SES; Stripe sends receipts and billing emails. Refund/dispute processing, daily billing reconciliation, billing retention, and download endpoints are not implemented. The billing contract and rollout gaps are documented in [Docs/Billing.md](Docs/Billing.md).

## Trust boundaries

- AWS KMS holds the entitlement private key. The service can request Ed25519 signatures but cannot export the private key.
- The Sparkle and Apple release keys do not belong to this service. The GlassEQ release workflow builds and signs updates separately.
- The ECS task role must not be able to upload, replace, or delete update artifacts.
- The ECS task role may send email through SES only from the verified GlassEQ sender identity.
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
| `GLASSEQ_EMAIL_LOOKUP_HMAC_KEY` | Unpadded Base64URL encoding of the 32-byte key used for recovery-email lookups |
| `GLASSEQ_DATABASE_ENCRYPTION_KEY` | Unpadded Base64URL encoding of the 32-byte key that encrypts email addresses and delivery credentials |
| `GLASSEQ_EMAIL_FROM` | Verified SES sender address, such as `licenses@glasseq.app` |
| `GLASSEQ_HTTP_ADDRESS` | Listen address, defaults to `:8080` |

Keep the encryption and HMAC keys stable across deployments. Store them in the deployment's secret manager; do not commit them.

Stripe API access is optional. Supplying any of these variables requires all three:

| Variable | Purpose |
| --- | --- |
| `GLASSEQ_STRIPE_SECRET_KEY` | Stripe secret or restricted API key; store it in AWS Secrets Manager |
| `GLASSEQ_STRIPE_PERPETUAL_PRICE_ID` | Environment-specific perpetual Price ID |
| `GLASSEQ_STRIPE_MONTHLY_PRICE_ID` | Environment-specific monthly Price ID |

The Stripe client derives test or live mode from the API key and rejects a response from the other environment. The configured IDs remain server-owned and are never accepted from callers.

Before enabling billing or changing its Stripe catalog, add these variables to the preflight task's environment:

| Variable | Purpose |
| --- | --- |
| `GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID` | Environment-specific perpetual Product ID |
| `GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID` | Environment-specific monthly Product ID |

The preflight task also needs the three Stripe API variables above. Run it with the same server image:

```sh
glasseqserver check-stripe-catalog
```

The command retrieves both configured Prices and their Products. It returns a nonzero status unless their environment, active Products, `txcd_10202001` tax code, tax-exclusive EUR amounts, and one-time or monthly billing shapes match GlassEQ's fixed catalog. It does not validate the Payment Links.

### Stripe webhook

The webhook is disabled unless all of these variables are supplied alongside the Stripe API variables:

| Variable | Purpose |
| --- | --- |
| `GLASSEQ_STRIPE_WEBHOOK_SECRET` | Signing secret for the Stripe webhook endpoint |
| `GLASSEQ_STRIPE_PERPETUAL_LINK_ID` | Payment Link ID for the perpetual plan |
| `GLASSEQ_STRIPE_MONTHLY_LINK_ID` | Payment Link ID for the monthly plan |
| `GLASSEQ_STRIPE_PERPETUAL_PRODUCT_ID` | Product expected on purchased perpetual line items |
| `GLASSEQ_STRIPE_MONTHLY_PRODUCT_ID` | Product expected on monthly Checkout, Subscription, and Invoice line items |

Point the Stripe event destination to `POST /v1/stripe/webhook` with the pinned Stripe API version. The handler accepts the raw signed body, enforces a 256 KiB limit and Stripe's five-minute signature tolerance, and returns a non-2xx response when processing fails so Stripe can retry. Configure only the supported events listed in `Docs/Billing.md`.

The webhook handles the four Checkout Session events (`completed`, `async_payment_succeeded`, `async_payment_failed`, and `expired`), `invoice.paid`, `invoice.payment_failed`, `invoice.updated`, and `customer.subscription.updated` / `deleted`. A Checkout Session from one of the configured Payment Links establishes the local purchase row. Fulfillment atomically records the event outcome, creates one license and hashed key with an encrypted seven-day delivery copy, inserts the delivery outbox row, and fulfills the purchase. Monthly fulfillment also creates the subscription projection. An Invoice or Subscription event received before its Checkout Session is recorded as unowned; the later Checkout event hydrates current Stripe state.

Monthly events retrieve the current Checkout, Subscription, and relevant Invoices outside transactions. Access uses paid invoice line periods, not an unpaid renewal's Subscription period. Payment recovery retains the fourteen-day window, customer cancellation removes that window, and existing terminal license states cannot be restored by renewal events. Migration `00006_billing_revision.sql` adds an order revision: if another reconciliation commits during the Stripe reads, the stale attempt rolls back and retries. Every monthly reconciliation, including a no-change result, advances that revision.

Duplicate and concurrent webhook events are safe to retry. Invalid owned purchases return a retryable response and require investigation. Valid events for unowned objects are recorded as `ignored_unowned`. Perpetual purchases already refunded or disputed remain rejected pending terminal-state processing.

Apply migrations before enabling the webhook. Keep production purchases disabled until refund/dispute processing, daily reconciliation, retention, and the documented rollout checks are complete. SES acceptance and sender verification remain deployment checks.

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
- `POST /v1/recovery-requests` for requesting email recovery. Requires an `Idempotency-Key` header.
- `POST /v1/recovery-sessions` for exchanging a one-time bearer recovery token for a management session. Requires an `Idempotency-Key` header.
- `POST /v1/stripe/webhook` for signed Stripe purchase and subscription events when billing is configured.

Successful activation responses remain replayable for 24 hours. Failed requests are evaluated again rather than cached. The service removes expired replay and rate-limit rows in bounded background batches.

Refresh and current-installation deactivation authenticate with the activation token returned during activation. Deactivation retains the token hash so repeating that operation returns 204, while other uses of the deactivated token fail.

Management sessions authenticate with the license key and return a short-lived bearer token. The service stores only its SHA-256 hash. Slot listing exposes opaque activation IDs and timestamps, not device details. Remote release is idempotent and cannot affect another license's activation.

License-key rotation requires a management session and an idempotency UUID. A license can rotate once every 24 hours. A successful rotation consumes the management session, retains only the previous revoked key, and leaves existing activations intact. The encrypted success response remains replayable for 24 hours, including after the management session expires, so a lost HTTP response does not lose the new key.

Well-formed recovery requests always return the same `202` response for known, unknown, invalid, and rate-limited email addresses. Requests are limited to three attempts per normalized email and 20 attempts per IP address each hour. Every non-limited address produces the same small lookup job, and the service stores that job with the encrypted idempotency replay in one transaction. The HTTP path does not look up licenses or create tokens.

A background worker resolves lookup jobs and atomically creates hashed 30-minute tokens with encrypted delivery data for matching licenses. Failed preparation jobs are deferred for one minute so they cannot block later lookups or existing deliveries. The dispatcher claims pending deliveries without holding a database connection during the SES call. It does not send tokens with less than five minutes remaining. After SES accepts the message, it deletes the outbox row. A crash after SES accepts a message but before the database acknowledgement can send the same token again.

A separate dispatcher sends the initial license key from the encrypted delivery outbox through SES. After SES accepts it, the dispatcher removes the outbox row and encrypted delivery copy. A retry after an ambiguous SES response can send the same key twice. Expired undelivered copies are cleared by the cleanup worker.

Recovery tokens can be exchanged once while the associated license remains active. The exchange consumes the recovery token, creates a 15-minute management session, and stores an encrypted response atomically. Successful exchanges can be replayed with the same idempotency key for 24 hours, including after the recovery token expires.

## Checks

```sh
go test -race -p 1 ./...
go vet ./...
docker build --build-arg SOURCE_REVISION=development .
```

Database migrations run separately from the application. Production deployment should run the pinned Goose image as a one-shot task before replacing the ECS service.

Published images must set `SOURCE_REVISION` to the exact Git commit used for the build. The image records that revision in its OCI metadata and includes the AGPL license text.

## License

GlassEQ Server is licensed under `AGPL-3.0-or-later`. See `LICENSE`.
