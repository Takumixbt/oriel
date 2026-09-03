# Earn form — copy/paste answers

Open: https://superteam.fun/earn/listing/t3n-agent-build-challenge → **Submit Now**

## Link

```
PASTE_PUBLIC_GOOGLE_DOC_URL_HERE
```

The listing requires a **public Google Doc**. Put the GitHub URL inside the Doc, not as the primary Link unless Earn also accepts it — use the Doc URL here.

## Tweet (optional, bonus)

After you post on X tagging @terminal3io:

```
PASTE_X_POST_URL_HERE
```

Suggested post copy:

```
Built Oriel for the @terminal3io T3N Agent Build Challenge — private qualification so an agent’s exact DID + version earns short-lived access only after surviving tenant-private adversarial tests on T3N.

Repo: https://github.com/Takumixbt/oriel
```

## Other info

```
Oriel is private qualification infrastructure for autonomous agents on T3N. An enterprise target must pass a tenant-private adversarial probe (signed target response + separate observer receipt) before its exact DID and version label can read a protected support record. Failure, version drift, wrong scope, expiry, and revocation all deny with no data.

Public repo: https://github.com/Takumixbt/oriel
Verified locally: npm run demo, 11 TypeScript tests, 14 Rust unit tests + 1 doc test, wasm32-wasip2 build, CI green.
Contract source 0.2.0; release WASM SHA-256 295820dfb875f051d64238f4bc7cf936040de9fbd869f8a9b586b23798d894a7.
Four actionable SDK/platform findings are in docs/BUGS.md.
Preferred post-challenge path: hand Oriel to Terminal 3 to host and maintain, with a 30-day transition and ops runbook in docs/HANDOVER.md.
```

## Eligibility questions

### 1. Email address

```
PASTE_YOUR_EMAIL_HERE
```

### 2. What is your DID generated from the page?

Use the DID from https://go.terminal3.io/adk-community (the claim page), **not** Oriel’s contract or demo DIDs.

```
did:t3n:PASTE_YOUR_CLAIM_PAGE_DID_HERE
```

### 3. Would you want to continue running this / pass it to us to run it?

```
Pass it to Terminal 3 to host and maintain. I will support a 30-day transition. The MIT-licensed repo includes a full handover runbook (docs/HANDOVER.md): registration, ACL rewrite on new contract IDs, grants, key rotation, policy versioning, monitoring, rollback, and acceptance checks. Happy to join the startup/listing program if useful, but preferred path is T3 hosting.
```
