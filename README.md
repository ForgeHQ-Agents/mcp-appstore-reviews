# mcp-appstore-reviews

A small, **reviews-only** MCP server for the Apple App Store, backed by the
[App Store Connect API](https://developer.apple.com/documentation/appstoreconnectapi).
It lets an agent read customer reviews and publish or delete developer responses —
and deliberately nothing else.

## Why so narrow?

The capability boundary *is* the trust guarantee. This server exposes only the
three review tools below. There is intentionally **no** build, release,
submission, pricing, in-app-purchase, certificate, profile, or beta-tester tool,
so the App Store Connect key you give it can't be used to do any of those things.
Scope the key itself narrowly too (the **Customer Support** role is enough).

It is also **dependency-free** — pure Node 18+ (`fetch` + built-in `crypto`),
no third-party packages — so there is no supply chain to audit beyond this one
file (`index.mjs`).

## Tools

| Tool | Description |
| --- | --- |
| `list_reviews` | List reviews for an app (newest first by default), including any existing developer response and its id. Filters: `territory`, `rating`, `sort` (`recent`/`favorable`/`critical`), `limit`. |
| `respond_to_review` | Publish a developer response to a review (`reviewId`, `responseBody`). |
| `delete_review_response` | Delete a developer response by its `responseId` (from `list_reviews`). |

## Authentication

Create an App Store Connect API key (Users and Access → Integrations → App Store
Connect API). Use the **Customer Support** role — it can manage reviews without
the broader powers of Admin. Then provide:

| Env var | What |
| --- | --- |
| `APP_STORE_CONNECT_ISSUER_ID` | Issuer ID shown at the top of the Integrations page |
| `APP_STORE_CONNECT_KEY_ID` | Key ID of the API key |
| `APP_STORE_CONNECT_PRIVATE_KEY_PATH` | Path to the downloaded `.p8` private key file |

The private key is read only to sign a short-lived ES256 JWT for Apple; it is
never logged, copied, or sent anywhere but Apple's API.

## Run

```bash
# stdio MCP server
APP_STORE_CONNECT_ISSUER_ID=... \
APP_STORE_CONNECT_KEY_ID=... \
APP_STORE_CONNECT_PRIVATE_KEY_PATH=/path/to/AuthKey_XXXX.p8 \
npx -y github:ForgeHQ-Agents/mcp-appstore-reviews
```

The agent passes the app's numeric App Store ID as `appId` (find it in App Store
Connect → your app → App Information, or in the app's App Store URL).

## Test

```bash
npm test   # node --test, zero dependencies
```

## License

MIT
