# Security policy

Do not open a public issue containing credentials, private test material, customer data, raw probe evidence, or exploit payloads against a live deployment.

For a private deployment, report suspected key exposure, qualification forgery, caller-identity confusion, canary disclosure, ACL bypass, or protected-data return on denial to the deployment owner through its private incident channel. Revoke affected qualifications and agent grants first, then preserve sanitized IDs and digests for investigation.

The repository contains synthetic records only. Example DIDs and key-shaped values are nonfunctional test data generated at runtime.

Supported release: `0.1.x` during the challenge. This prototype has not received an independent security audit.
