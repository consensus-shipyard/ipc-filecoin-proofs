# ipc-filecoin-proofs — Product Ideas & Use Cases

## What This Library Does

`ipc-filecoin-proofs` generates and verifies cryptographic Merkle proofs of Filecoin
blockchain state and events. It allows any party to prove, with minimal data, that:

- A specific value was stored in a smart contract at a given block
- A specific event was emitted by a contract in a given block

Verification requires **no network access** — just the proof bundle (a few KB of witness
blocks). This makes it ideal for trustless cross-chain and off-chain applications.

---

## Product Ideas

---

### 1. IPC Bridge Relayer (Core Use Case)

**What it is:** A service that watches the Filecoin parent chain and relays proven state
updates and cross-chain messages down to IPC child subnets.

**How it works:**
- Runs `generate_proof_bundle()` for each new finalized Filecoin epoch
- Delivers `UnifiedProofBundle` to child subnet contracts
- Child subnet verifies the proof on-chain and processes messages

**Why it matters:** This is the exact problem the library was built for. The IPC
(InterPlanetary Consensus) framework needs trustless message passing between
Filecoin (parent) and EVM-compatible subnets (children).

**Monetization:** Infrastructure fee per relayed message, or run as a public good
within the IPC protocol.

---

### 2. Proof-as-a-Service REST API

**What it is:** A hosted HTTP API that accepts a query (contract address, storage slot
or event signature) and returns a verifiable proof bundle.

**Endpoints:**
```
POST /v1/storage-proof
  { "rpc_url": "...", "actor_id": 181949, "slot": "0x...", "height": 1234567 }
  → { "bundle": { ... } }

POST /v1/event-proof
  { "rpc_url": "...", "event_sig": "Transfer(address,address,uint256)", "height": ... }
  → { "bundle": { ... } }
```

**Why it matters:** Developers don't want to run their own Lotus node or write Rust.
A simple REST API unlocks the library for JavaScript, Python, Go, and browser clients.

**Monetization:** API key tiers (free / pro / enterprise), per-proof billing.

---

### 3. Cross-Chain Oracle / Data Feed

**What it is:** A service that continuously proves Filecoin contract state to other
blockchains (Ethereum, Base, Arbitrum, Polygon, etc.).

**Examples:**
- Prove the current FIL total supply to an Ethereum contract
- Prove deal/sector state on Filecoin to a DeFi protocol on Ethereum
- Prove IPC subnet configuration changes to downstream chains

**How it works:**
- Off-chain service generates storage proof bundle periodically
- Submits to a Solidity `OracleReceiver` contract that verifies the bundle
- Verified value is then available to other contracts on that chain

**Why it matters:** Existing oracles (Chainlink, Pyth) don't cover Filecoin-native state.
This fills a gap in the cross-chain data landscape.

**Monetization:** Subscription model for data feeds; pay-per-update for ad hoc queries.

---

### 4. On-Chain Solidity Verifier Contract

**What it is:** A Solidity library/contract that accepts an ABI-encoded `UnifiedProofBundle`
and verifies the IPLD Merkle proofs fully on-chain.

**How it works:**
- The Rust library generates the proof (off-chain, cheap)
- Proof is ABI-encoded and submitted as calldata to an EVM chain
- Solidity contract verifies HAMT/AMT traversals against trusted CIDs
- No oracle, no relayer trust required

**Why it matters:** Achieves fully trustless cross-chain state verification without
any centralized components. The holy grail of cross-chain communication.

**Monetization:** Open-source core verifier; charge for audit, integration support,
and managed relayer services.

---

### 5. Filecoin Event Indexer with Proofs

**What it is:** A block explorer / indexer service that not only indexes Filecoin
events but attaches cryptographic proof to each indexed event.

**Features:**
- Query events by contract, signature, topic
- Download proof bundle for any historical event
- Proof can be used to dispute or verify event claims off-chain

**Why it matters:** Event indexers like The Graph index data but provide no
cryptographic guarantee. This adds provability to indexed data.

**Monetization:** SaaS indexer subscription; pay-per-proof download for high-value events.

---

### 6. Deal / Sector Storage Verification

**What it is:** Use the library's storage proof capabilities to prove that a specific
storage deal is still active on Filecoin to external chains or clients.

**How it works:**
- Prove a storage deal's state slot in the built-in Storage Market actor
- Deliver proof to an off-chain verifier or another chain
- Use as a cryptographic receipt that data was stored at a specific time

**Why it matters:** Enables use cases like "pay only when proven stored" in DeFi
protocols, cross-chain storage insurance, and data notarization services.

**Monetization:** Per-proof fee; integration into storage deal platforms.

---

### 7. IPC Subnet Bootstrap / Config Verifier

**What it is:** A tool that proves an IPC subnet's initial configuration (validator set,
power table, genesis state) is correctly derived from the parent Filecoin chain.

**How it works:**
- Generate storage proofs for the gateway contract's subnet registration slots
- New subnet members verify the proof before participating
- Prevents subnet configuration spoofing at launch

**Why it matters:** Critical security property for IPC subnet launch and upgrades.
Prevents rogue subnet configurations from being accepted by nodes.

**Monetization:** Part of IPC protocol tooling; funded by Protocol Labs / IPC grants.

---

### 8. Monitoring & Alerting Service

**What it is:** A service that watches specific Filecoin contracts for state changes
or events and delivers proven notifications to subscribers.

**Features:**
- "Notify me when contract 0x... emits `NewTopDownMessage` for my subnet"
- Webhook delivery with attached proof bundle
- Subscribers can independently verify notifications are genuine

**Why it matters:** Existing monitoring tools (Tenderly, OpenZeppelin Defender) don't
cover Filecoin. Cross-chain monitoring with built-in provability is a new category.

**Monetization:** SaaS subscription; alert volume tiers.

---

## Summary Table

| Product | Effort | Revenue Model | Who Wants It |
|---|---|---|---|
| IPC Bridge Relayer | Medium | Protocol fee | IPC subnet operators |
| Proof-as-a-Service API | Low | API billing | Any Filecoin developer |
| Cross-Chain Oracle | Medium | Subscription | DeFi protocols, dApps |
| Solidity Verifier Contract | High | Services + audit | dApp builders |
| Event Indexer with Proofs | Medium | SaaS | Block explorers, analysts |
| Deal/Sector Verification | Medium | Per-proof fee | Storage clients, DeFi |
| Subnet Config Verifier | Low | Grants / OSS | IPC ecosystem |
| Monitoring & Alerting | Low | Subscription | DevOps, dApp operators |

---

## Near-Term Quick Wins (Code Already Supports These)

1. **Wrap `main.rs` as a CLI tool** — add `--actor`, `--slot`, `--height`, `--output-json` flags.
   Immediate utility for developers without any API.

2. **Add `--serve` mode** — start an HTTP server. No extra logic needed; just wire up the
   existing `generate_proof_bundle()` to a route handler.

3. **Publish proof bundles as JSON** — the `UnifiedProofBundle` is already `Serialize`.
   Piping `cargo run --bin proofs > proof.json` already works.

4. **Ship as a crate on crates.io** — the library is functionally complete for storage
   and event proofs. Publishing would allow broader adoption immediately.

---

*Generated from codebase analysis of `consensus-shipyard/ipc-filecoin-proofs`*
