# Billing and license delivery

## Ownership

Stripe Managed Payments owns Checkout, tax, receipts, invoices, refunds, billing email, and customer billing management. The public site links directly to two Stripe Payment Links, one for the EUR 29.99 perpetual license and one for the EUR 2.99 monthly subscription. GlassEQ Server owns license issuance, entitlements, activation slots, initial license-key email, and purchase-email recovery. Audio, profiles, and diagnostics stay on the Mac.

The base catalog is in EUR. Managed Payments Adaptive Pricing may present and charge another currency. Fulfillment binds to the configured Stripe Price and Product IDs, not the displayed currency or converted amount. Both Products must use tax code `txcd_10202001` and tax-exclusive pricing. The monthly plan has no trial. The subscription uses eight Smart Retry attempts over two weeks and cancels after the final failure; the entitlement projection relies on that schedule.

Stripe Link handles subscription cancellation, payment methods, billing addresses, order history, and billing email. A Stripe receipt is not a GlassEQ recovery credential. The purchase inbox remains the authority for a one-time recovery token, which grants a short management session that can rotate the license key and manage activation slots.

## Current implementation

The service accepts a raw Stripe webhook at `POST /v1/stripe/webhook` when its Stripe API key, catalog IDs, Payment Link IDs, and webhook signing secret are configured. It checks the `Stripe-Signature` header with Stripe's five-minute tolerance before parsing the body. The body is limited to 256 KiB. The event API version must match the pinned `stripe-go` preview version, and test/live mode must match the API key. Stripe object retrieval has a 15-second deadline, 1 MiB response limit, and no redirects.

The webhook accepts these snapshot event types:

| Event | Use |
| --- | --- |
| `checkout.session.completed`, `checkout.session.async_payment_succeeded` | Establish a Payment Link purchase and fulfill when current Stripe state proves payment |
| `checkout.session.async_payment_failed`, `checkout.session.expired` | Record an unpaid purchase failure without revoking a later successful payment |
| `invoice.paid`, `invoice.payment_failed`, `invoice.updated` | Reconcile a known monthly subscription against current Stripe state |
| `customer.subscription.updated`, `customer.subscription.deleted` | Reconcile a known monthly subscription, cancellation, or retry exhaustion |

Events are notifications, not authoritative snapshots. The processor retrieves the current Checkout Session and, for monthly events, its Subscription and relevant Invoices. It accepts a Checkout Session only when its `payment_link`, mode, single line item, quantity, configured Price and Product, and Managed Payments state match the selected plan. A Payment Link purchase has no server-created order or caller-supplied metadata. The first accepted Session event inserts a local purchase row keyed by the Stripe Session ID. An unrelated Payment Link or API-created Checkout Session is ignored.

For a paid perpetual purchase, the Session must be complete, contain an accepted terms consent and purchase email, identify a Customer, and have a succeeded PaymentIntent with a paid, undisputed, unrefunded Charge. For a paid monthly purchase, the Session must identify a Customer and Subscription, and the initial Invoice must be paid. Subscription and Invoice line items must match the fixed monthly Price, Product, quantity, and Subscription item. A payment can be delayed; an unpaid Session does not issue a license.

Fulfillment happens in one PostgreSQL transaction. It records the event outcome, creates one license and active key, stores a hashed key plus an encrypted delivery copy, creates an outbox row, and marks the purchase fulfilled. Monthly fulfillment also creates the subscription projection. Stripe and SES calls happen outside database transactions. Duplicate events and concurrent deliveries cannot issue a second license for the same Session. A competing monthly reconciliation changes the order revision; stale hydration rolls back and retries.

The purchase email from `customer_details.email` is the license-delivery and recovery address. The service does not silently substitute the Stripe Customer email. It stores the address encrypted and an HMAC for recovery lookup. The license key and recovery token are encrypted while waiting for SES delivery. The service sends only these two product emails; Stripe sends receipts and billing email. SES acceptance removes the outbox row, and successful license delivery also clears the encrypted key copy. A crash after SES accepts an email but before the database acknowledgement can send the same credential twice. Expired delivery copies are removed in bounded cleanup batches.

An Invoice or Subscription event that arrives before its Session is recorded as unowned. When the Session event arrives, the processor retrieves current state and can fulfill the purchase or apply cancellation. This still depends on receiving the Session event; daily reconciliation is required before production rollout to repair events missed beyond Stripe's retry window.

## Monthly entitlement projection

The client receives the stored monthly state and times in its signed entitlement. Its `billing_period_end` comes from a validated paid Invoice line, never from an unpaid Subscription period.

| Stripe observation | Stored state | `recovery_until` |
| --- | --- | --- |
| Initial or renewal Invoice paid and Subscription active | `active` | `billing_period_end + 14 days` |
| Renewal payment failed while Stripe can recover it | `recovering` | At least `billing_period_end + 14 days` |
| Customer requested cancellation at period end | `ending` | `billing_period_end` |
| Customer removed pending cancellation while paid | `active` | `billing_period_end + 14 days` |
| Customer canceled, or scheduled cancellation reached its end | `lapsed` | `billing_period_end` |
| Stripe ended the Subscription after retries or marked it unpaid | `lapsed` | Preserve the last payment-recovery deadline |
| A later payment restores an eligible Subscription | `active` | New `billing_period_end + 14 days` |

The processor checks the latest Invoice and, for Invoice events, the event's current Invoice. A late payment of an older renewal can restore access, but an unpaid newer period cannot extend it. A canceled monthly Subscription remains paid through its paid period. A terminal `refunded`, `charged_back`, or `revoked` license state takes precedence over later subscription events. GlassEQ's signed monthly entitlement retains its separate seven-day client grace period.

## Work before production purchases

Refund and dispute processing is not merged into this branch. The intended rule is that a full successful refund or opened dispute terminates the affected license. Before terminating a monthly license, the service must confirm Stripe will not bill that Subscription again. A partial refund requires an operator decision. A won or withdrawn dispute may restore access only after current Stripe state proves payment and eligibility. Manual revocation is never reversed by a later billing event.

The service also needs a bounded daily reconciliation of monthly subscriptions, retention for processed Stripe events and abandoned purchases, and operator alerts for repeated webhook or SES failures. Webhook delivery retries are useful but are not a durable substitute for reconciliation.

Before switching production links on:

1. Verify Managed Payments terms, public terms/privacy links, tax code, Price/Product IDs, Payment Link settings, and the pinned webhook API version in the production Stripe account. Run `glasseqserver check-stripe-catalog`; it checks Prices and Products but does not inspect Payment Links.
2. Verify the SES domain identity and production sending access in `eu-north-1`. Give the ECS task role only the required `ses:SendEmail` permission for the verified sender, plus its existing KMS permissions.
3. Deploy the public webhook through the Application Load Balancer with TLS. Store the Stripe API key, webhook signing secret, encryption keys, and HMAC keys in the secret manager. Do not log Stripe payloads, email addresses, license keys, or recovery tokens.
4. Verify sandbox and production separately: one-time and monthly purchases, delayed payment, renewal failure and recovery, cancellation, refund, dispute, duplicate and out-of-order events, SES delivery, and recovery-token exchange. Confirm that retries after database or SES failure neither lose a purchase nor issue a second license.

Do not reuse sandbox keys, link IDs, catalog IDs, or webhook signing secrets in production. Database migrations run before replacing the ECS service. The Goose image and its digest are pinned in `compose.yaml` for local use; resolve and pin the deployment image digest separately.

## References

- [Managed Payments and Link customer management](https://docs.stripe.com/payments/managed-payments/how-it-works)
- [Payment Links](https://docs.stripe.com/payment-links)
- [Fulfill Checkout orders](https://docs.stripe.com/checkout/fulfillment)
- [Verify webhook signatures](https://docs.stripe.com/webhooks/signature)
- [Subscription webhooks](https://docs.stripe.com/billing/subscriptions/webhooks)
- [Smart Retries](https://docs.stripe.com/billing/revenue-recovery/smart-retries)
- [Amazon SES production access](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html)
