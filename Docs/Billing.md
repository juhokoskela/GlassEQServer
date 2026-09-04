# Billing protocol

## Purpose

This document defines how GlassEQ Server creates Stripe Checkout Sessions, turns Stripe events into licenses, and projects subscription state into the entitlement model. It is the server-side companion to the client entitlement protocol in the GlassEQ repository.

The first implementation targets Stripe Managed Payments and AWS `eu-north-1`. Product and price identifiers below are sandbox values. Production identifiers must be supplied separately and must never be inferred from the sandbox configuration.

## Fixed product decisions

| Plan | Price | Sandbox product | Sandbox price |
| --- | --- | --- | --- |
| `perpetual_v1` | EUR 29.99 plus tax | `prod_VBtSu7EmXGUrL8` | `price_1UBVfNEC4w9ZWN2YlB59OzfZ` |
| `monthly` | EUR 2.99 per month plus tax | `prod_VBtQ3VslhU3Tgv` | `price_1UBVdzEC4w9ZWN2Y8pOBCyAE` |

- A license permits two active installations.
- A perpetual license includes official v1.x releases.
- The monthly subscription uses eight Smart Retry attempts over two weeks. Stripe cancels the subscription after the final failed attempt.
- Monthly entitlements remain usable throughout that recovery schedule, followed by the existing seven-day client grace period.
- Checkout returns to `https://glasseq.app/checkout/success` or `https://glasseq.app/checkout/cancel`.
- License-delivery and recovery emails are sent from `glasseq.app` through Amazon SES.

## Ownership and trust boundaries

Stripe is authoritative for payment, refund, dispute, and subscription state. PostgreSQL stores the normalized state used by GlassEQ. Event payloads are notifications, not authoritative snapshots.

The public website may request a Checkout Session, but it does not choose a Stripe Price ID, amount, currency, policy version, mode, or return URL. GlassEQ Server derives those values from the selected plan and its environment-specific configuration.

Stripe events enter AWS through an EventBridge partner event source. There is no public Stripe webhook endpoint and no Stripe webhook signing secret. The event path is:

```text
Stripe -> EventBridge partner source -> EventBridge rule -> SQS Standard queue -> GlassEQ Server worker
```

A Standard queue is sufficient. Stripe does not guarantee event ordering, so FIFO ordering would not remove the need for idempotent processing and current-state reconciliation.

AWS must enforce these boundaries:

- The EventBridge partner source, rule, billing queue, and dead-letter queue live in `eu-north-1`.
- The billing queue policy permits `SendMessage` only from the exact EventBridge rule ARN.
- The GlassEQ Server task role may receive and delete messages only from the billing queue. It may not publish Stripe events or consume the dead-letter queue.
- The billing queue and dead-letter queue use the 14-day SQS retention maximum, server-side encryption, and policies that reject non-TLS access.
- The Stripe secret key lives in AWS Secrets Manager. It must not appear in source, task definitions, command arguments, URLs, or logs.
- The event destination pins one Stripe API version. Deployments reject envelopes from a different environment or unexpected source.

Stripe's EventBridge source must be associated in AWS within seven days of creating the event destination. Create both sides together when the infrastructure is ready, not during application development.

## Checkout Session API

`POST /v1/checkout-sessions` creates a hosted Checkout Session.

Request headers:

```http
Content-Type: application/json
Idempotency-Key: <random UUID v4>
```

Request body:

```json
{"plan":"perpetual_v1"}
```

The only accepted plans are `perpetual_v1` and `monthly`. The response is:

```json
{
  "checkout_url": "https://checkout.stripe.com/..."
}
```

The caller generates a cryptographically random UUID v4 and sends it in canonical lowercase form. The server rejects other UUID versions. Treat the key as a bearer capability until the Session expires. It authorizes replay of only that Checkout URL, not license or account access.

The server applies a short request deadline, permits 60 valid attempts per client IP per minute, and permits 20 new order reservations per client IP per hour. IPv6 addresses are grouped by `/64` for both limits. It uses the caller's idempotency UUID to derive a stable internal order ID and Stripe idempotency key. Repeating the same UUID and plan returns the same Stripe Session. Reusing it for another plan returns `409 Conflict`. Reusing it after that Session expires returns `409 Conflict` with `checkout_session_expired`; the caller must generate a new key.

The browser-facing endpoint permits cross-origin requests only from `https://glasseq.app`, with the minimum methods and headers needed for this request. CORS is not authentication; server-owned parameters, validation, idempotency, and rate limits remain the security boundary.

Creating a Session follows this sequence:

1. Validate the request and enforce the all-attempt IP rate limit.
2. Look for an existing order created with the idempotency key.
3. For a new request, enforce the reservation IP rate limit and insert a pending order reservation in one short database transaction.
4. Build the complete Stripe request from server-owned configuration.
5. Create or retrieve the Checkout Session outside any database transaction and within the task's four-request Stripe concurrency limit.
6. Attach a newly created Stripe Session ID to the reserved order in a short transaction.
7. Return the Stripe-hosted URL.

The stable order reservation and Stripe idempotency key make a retry safe if Stripe creates the Session but the process fails before its ID is attached. The order identifier is also sent as `client_reference_id` and metadata, so an event can recover the association and fulfillment can reject an unrelated Session. The schema must allow a reserved order to exist briefly without a Stripe Session ID.

Once an order has a Session ID, a replay retrieves that exact Session instead of repeating the create request. An unattached reservation repeats the idempotent create only until five minutes before Stripe's 24-hour idempotency boundary. After that cutoff, the reservation is treated as expired so a pruned Stripe key cannot create a replacement Session. Simultaneous requests using one idempotency key may receive a transient upstream or busy result; the caller retries the same request rather than generating a new key.

Stripe's `expired` and `complete` Session statuses are valid terminal states. An expired Session returns `checkout_session_expired`; a complete Session returns `checkout_session_complete` while fulfillment proceeds from Stripe events. Only an open, unexpired Session returns a Checkout URL.

Every Session has:

- exactly one line item with quantity one;
- the configured environment-specific Price ID;
- `payment` mode for `perpetual_v1` or `subscription` mode for `monthly`;
- Stripe Managed Payments enabled;
- the fixed success and cancel URLs;
- `client_reference_id`, `order_id`, `plan`, and `policy_version` set by the server;
- terms-of-service consent required.

The Stripe API version is the source-level constant `2026-07-29.preview`, pinned by the exact `stripe-go` preview release used by the server and shared with the EventBridge destination. Managed Payments is still a public preview, so that version must be verified with a sandbox purchase before production rollout. Production must not silently use Stripe's latest version.

## Accepted Stripe events

The EventBridge destination sends only the events in this table. The worker hydrates the current Stripe object before choosing the outcome.

| Event | Normalized outcome |
| --- | --- |
| `checkout.session.completed` | A valid paid Session moves its order to `paid`. A valid delayed payment stays `pending`. |
| `checkout.session.async_payment_succeeded` | A valid paid Session moves a `pending` or `failed` order to `paid`. |
| `checkout.session.async_payment_failed` | A still-unpaid Session moves its unfulfilled order to `failed`. |
| `checkout.session.expired` | A still-unpaid Session moves its unfulfilled order to `failed`. |
| `invoice.paid` | A paid initial Invoice moves its order to `paid`. A paid renewal moves the subscription to `active` and advances its period once. |
| `invoice.payment_failed` | An initial recoverable payment stays `pending`. A failed renewal moves the subscription to `recovering`. A terminal initial failure moves its order to `failed`. |
| `invoice.updated` | Reconciles the same paid, pending, failed, or recovering outcomes from the current Invoice. An update with no access effect records `no_change`. |
| `customer.subscription.updated` | A terminal initial Subscription moves its unfulfilled order to `failed`. Otherwise it reconciles `active`, `recovering`, `ending`, or `lapsed`. Removing a pending cancellation restores `active` when the paid Subscription is eligible. |
| `customer.subscription.deleted` | An unfulfilled initial Subscription moves its order to `failed`. A customer-requested cancellation becomes `lapsed` at the paid period end. Retry exhaustion preserves the payment-recovery deadline. A dispute leaves the terminal license state unchanged. |
| `refund.created` | Applies a successful full refund. Pending and partial refunds record `no_change`. |
| `refund.updated` | Applies a refund that has become successful. Other updates record `no_change`. |
| `refund.failed` | Records `no_change` and leaves access unchanged. |
| `charge.dispute.created` | Moves the affected license to `charged_back`. |
| `charge.dispute.closed` | A lost dispute leaves `charged_back` unchanged. A won or withdrawn dispute follows the restoration rules below. |

An order starts `pending` and may move to `failed` or `paid`. A `failed` order moves to `paid` only when current Stripe state later proves payment succeeded. A `paid` order is durable work waiting for license fulfillment. The event worker attempts fulfillment immediately, and a bounded background sweep retries paid orders. `fulfilled` is terminal.

Adding an event type is a code and infrastructure change. Unknown, malformed, or untrusted messages are rejected and eventually moved to the dead-letter queue so configuration drift cannot pass silently.

## Event processing

SQS delivery and Stripe events are both at least once. Processing must be safe under duplication, concurrency, delay, and reordering.

For each message, the worker:

1. Parses a bounded EventBridge envelope and validates its source, account environment, event API version, event ID, event type, object ID, and creation time.
2. Inserts an unprocessed event ID into `stripe_events`, or recognizes an already completed event.
3. Fetches the current Checkout Session, Invoice, Subscription, Refund, Dispute, Charge, or PaymentIntent needed to resolve the affected order or license. Stripe calls happen outside database transactions.
4. Applies one normalized state transition and marks the event processed in a short database transaction.
5. Deletes the SQS message only after the transaction commits.

Transient Stripe, database, or network failures leave the message for retry. A permanently invalid message reaches the dead-letter queue after a small bounded receive count. Operators must have a documented command to inspect and redrive a corrected dead-letter message without logging its body.

A valid accepted event may refer to a Checkout Session or payment that this deployment never created, including a Dashboard test purchase. The worker marks it processed with `ignored_unowned` and deletes the SQS message. An owned object with broken metadata or a violated invariant is not ignored; it retries and reaches the dead-letter queue for investigation.

`stripe_events` prevents duplicate work but does not establish ordering. Every transition compares hydrated current Stripe objects with stored identifiers and timestamps. An older event may trigger reconciliation, but it must not overwrite newer normalized state.

The final transaction locks the event row and checks `processed_at` again before changing domain state. Two workers may fetch the same Stripe objects, but only one commits the transition. The `outcome` column stores a bounded code such as `paid`, `failed`, `active`, `recovering`, `ending`, `lapsed`, `refunded`, `charged_back`, `restored`, `no_change`, or `ignored_unowned`.

The worker performs no Stripe or KMS call while holding a database transaction, row lock, or advisory lock.

## Purchase fulfillment

A completed Checkout event is only a prompt to inspect the Session. The worker retrieves the Session and line items and verifies:

- `client_reference_id` and metadata identify the pending order;
- plan, policy version, mode, Product ID, Price ID, and quantity match that order;
- the Session belongs to the configured Stripe environment;
- the Session was created with Managed Payments and records acceptance of the expected terms;
- `customer_details.email` is present and valid;
- the payment is complete.

For a perpetual purchase, `payment_status` must be `paid`. For a monthly purchase, the initial Invoice must be paid and the Subscription must be active. A completed Session with delayed or incomplete payment stays pending until the asynchronous success or `invoice.paid` event reconciles it.

Fulfillment uses one database transaction to:

1. lock the paid order;
2. normalize `customer_details.email`, encrypt it with the database encryption key, and compute its lookup HMAC with the email lookup key;
3. create exactly one license with that recovery email ciphertext and lookup hash;
4. create exactly one active license key;
5. store only the key hash plus an encrypted delivery copy that expires within seven days;
6. create the monthly subscription projection when applicable;
7. mark the order fulfilled;
8. enqueue a durable license-delivery email record.

The Checkout Session email is the recovery and delivery address. It wins if it differs from the email currently stored on the Stripe Customer. The service does not silently fall back to the Customer email because fulfillment already requires the Session email.

The transaction contains no Stripe, KMS, SQS, or SES call. A separate dispatcher publishes a `license_delivery` message to the same encrypted FIFO queue used by recovery email. The email consumer distinguishes the message type and deduplicates the stable delivery ID before sending through SES. Stripe remains responsible for receipts and billing emails; GlassEQ sends only the license credential and product-specific recovery messages.

Fulfillment stores the minimum Stripe identifiers needed to resolve later invoices, refunds, and disputes. It does not store card data, billing addresses, Stripe payloads, or tax details. Before enabling the endpoint, the implementation migration must add the request ID and payment reference, allow `stripe_checkout_session_id` to be null while an order is reserved, and add the license-delivery outbox.

## Monthly subscription projection

The database has four billing states. The client receives the resulting state and times in its signed entitlement.

| Stripe observation | Stored state | `recovery_until` |
| --- | --- | --- |
| Initial or renewal Invoice paid and Subscription active | `active` | `billing_period_end + 14 days` |
| Renewal payment failed while Stripe can still recover it | `recovering` | Keep at least `billing_period_end + 14 days` |
| Customer requested cancellation at period end | `ending` | `billing_period_end` |
| Customer removed a pending cancellation while the Subscription remains paid | `active` | `billing_period_end + 14 days` |
| Customer canceled immediately, or a scheduled cancellation reached its end | `lapsed` | `billing_period_end` |
| Stripe ended the Subscription after payment retries, or marked it unpaid | `lapsed` | Preserve the last payment-recovery deadline |
| A later payment restores an eligible Subscription | `active` | New `billing_period_end + 14 days` |

The worker uses the hydrated Subscription's `cancel_at_period_end` and `cancellation_details.reason` to distinguish a customer request, payment failure, and dispute. A terminal license state takes precedence over the subscription projection.

Smart Retries are an operational dependency of this model. The production Stripe account must retain eight attempts over two weeks with cancellation as the final action. Any change to that schedule requires reviewing the projection and client grace period together.

An older event never shortens a recovery deadline. A current customer cancellation deliberately shortens it to the paid period end, while a refund or chargeback deliberately replaces it with the terminal event time. The service records `last_paid_invoice_id` so the same paid Invoice cannot extend the period twice. It also records the reconciliation time and the Stripe event that prompted the current projection.

Monthly entitlement issuance remains unchanged:

- refresh is requested at most seven days after the last successful refresh;
- `exp` is exactly seven days after `recovery_until`;
- a refunded or charged-back license uses its terminal event time as `recovery_until`;
- a revoked license receives no entitlement.

## Refunds and disputes

Refund and dispute events are resolved through their current Stripe objects to the affected payment and license.

- A successful full refund of a perpetual purchase changes `licenses.state` to `refunded`. Perpetual licenses have no `terminal_at` because their entitlement logic has no terminal timeline.
- A successful full refund of any monthly Invoice, including a renewal, terminates the license. Before committing `refunded`, the worker cancels an active Stripe Subscription without proration or a new Invoice. It then sets `subscriptions.terminal_at` to the refund's effective time.
- A full monthly refund is therefore a terminating action. Use a partial refund or credit when the Subscription should continue.
- An opened dispute changes the license to `charged_back`. For a monthly license, the worker also cancels an active Subscription and sets `subscriptions.terminal_at` to the dispute's effective time.
- A failed refund does not change entitlement state.
- A partial refund requires an operator decision and never revokes a license automatically.
- A won or withdrawn dispute restores access only after current Stripe payment and subscription objects confirm that the license is paid and eligible.
- Manual revocation remains separate from billing state and is never reversed by a later Stripe event.

Stripe cancellation happens outside a database transaction. If its response is lost, the retry first hydrates the Subscription and treats an already-canceled result as success. The worker commits the terminal license state only after it confirms that Stripe will not bill the Subscription again. A later `customer.subscription.deleted` event cannot overwrite `refunded`, `charged_back`, or `revoked` license state.

For a monthly license, these terminal transitions start the existing seven-day signed-entitlement grace period. A perpetual license becomes ineligible for new activations and official services, but its cached offline entitlement has no expiry and cannot be remotely disabled.

## Reconciliation and retention

Events are the fast path, not the only repair mechanism. A bounded scheduled job must reconcile due monthly licenses against Stripe at least daily. It processes a small batch, performs Stripe requests without database connections, and updates each license in a short transaction. This repairs missed events and detects configuration drift without loading all subscriptions at once.

Retention is explicit:

- processed Stripe event records retain identifiers and outcomes for 30 days, longer than the 14-day billing-queue retention period, then are deleted in batches;
- unprocessed events are never removed by age alone;
- fulfilled order and license records are retained while required for license recovery and financial support;
- abandoned and failed Checkout orders are removed after a bounded support window;
- raw Stripe or SQS event bodies are not persisted;
- expired encrypted license-delivery copies and delivered email outbox rows are deleted in bounded background batches.

## Configuration and rollout gates

Sandbox and production use separate Stripe accounts or modes, keys, Price IDs, EventBridge destinations, queues, and secrets. A deployment preflight validates that both configured Prices exist, use EUR, have the expected recurring shape, and belong to the expected Products. Runtime requests trust the pinned Price IDs and do not repeat that network validation.

The billing feature stays disabled until all of these are true:

- Stripe Managed Payments terms are accepted and the selected API version is verified in sandbox.
- The public terms and privacy URLs are configured in Stripe Checkout settings.
- Production Product and Price IDs are recorded.
- Smart Retries and its final cancellation action are verified in production.
- Route 53 has finished publishing the `glasseq.app` records.
- The SES domain identity is verified in `eu-north-1` and SES production access is approved.
- EventBridge, SQS, dead-letter handling, Secrets Manager, IAM, and alarms are deployed from infrastructure as code.
- A sandbox purchase, delayed payment, renewal failure and recovery, cancellation, refund, dispute, duplicate event, out-of-order event, and dead-letter redrive have passed end-to-end verification.

## References

- [Set up Stripe Managed Payments](https://docs.stripe.com/payments/managed-payments/set-up)
- [Update Checkout for Managed Payments](https://docs.stripe.com/payments/managed-payments/update-checkout)
- [Create a Checkout Session](https://docs.stripe.com/api/checkout/sessions/create)
- [Fulfill Checkout orders](https://docs.stripe.com/checkout/fulfillment)
- [Use Stripe events with Amazon EventBridge](https://docs.stripe.com/event-destinations/eventbridge)
- [Use webhooks with subscriptions](https://docs.stripe.com/billing/subscriptions/webhooks)
- [Cancel subscriptions](https://docs.stripe.com/billing/subscriptions/cancel)
- [Configure Smart Retries](https://docs.stripe.com/billing/revenue-recovery/smart-retries)
- [Handle refunds](https://docs.stripe.com/refunds)
- [Respond to disputes](https://docs.stripe.com/disputes/responding)
- [Amazon EventBridge targets](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html)
- [Set Amazon SQS queue attributes](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html)
- [Request Amazon SES production access](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html)
