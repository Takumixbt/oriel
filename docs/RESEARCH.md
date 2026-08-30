# Challenge research brief

## Source and date

Primary source: [T3N Agent Build Challenge](https://superteam.fun/earn/listing/t3n-agent-build-challenge), inspected 30 August 2026. The listing was open with 35 submissions and six prize places at the time of inspection.

## Sponsor language that drives the build

The sponsor asks for a useful enterprise agent built with T3N that is easy to maintain and run after the challenge. The listing marks build quality—with usefulness and ease of maintenance—as **very important**. It also scores documentation and bug submission quality, rewards faster/earlier delivery, requires a public Google Doc with public GitHub repository, screenshots, and bugs, and asks entrants to state whether they will keep running the agent or hand it over with a process.

Official onboarding resources linked by the listing:

- https://go.terminal3.io/adk-community
- https://docs.terminal3.io/developers/adk/get-started/quickstart

## Product implications

| Listing signal | Oriel decision |
|---|---|
| useful for enterprises | protect sensitive agent capabilities, not consumer convenience |
| built with T3N | make caller DID, cluster time, private maps, ACLs, egress grants, WASI, and claims digest structural |
| maintainable post challenge | pure engine/adapters split, versioned JSON packs, pinned lockfile, CI, Docker, runbook |
| documentation quality | architecture, threat model, protocol, methodology, demo, critique, handover |
| bug quality | reproduce SDK dependency, type-safety, install-footprint, and ACL-rotation issues |
| handover | Terminal 3 hosting preference, 30-day transition, acceptance checklist |
| screenshots | repository-native architecture and verified lifecycle assets |

## Competitive judgment

With dozens of submissions, a generic research, summarization, support, or alerting agent is easy to understand but easy to replace. Oriel aims at a deeper Terminal 3-specific category: qualification infrastructure that makes private observed behavior a condition of runtime authority. Its strongest judge-facing proof is the complete negative/positive lifecycle, not a broad feature list.

## Devil's-advocate conclusion

The ambitious claim is defensible only if it stays narrow: Oriel does not prove arbitrary safety. It proves that one authenticated identity and build passed one private, versioned pack for one finite scope, then enforces that fact. The submission explicitly names target attestation and independently observed traces as production gaps so novelty does not outrun evidence.
