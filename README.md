## Filecoin Proofs CLI

Build inclusion proofs for Filecoin message receipts and EVM storage, and verify them offline. This CLI talks to a Lotus node over JSON-RPC.

### Requirements

- Rust stable (via rustup)
- Access to a Lotus RPC endpoint

### Build

```bash
cargo build --release
```

### Usage

```bash
# Receipt inclusion proof
proofs receipt <rpc_url> <height_h_plus_1> <message_cid>

# EVM storage proof
proofs storage <rpc_url> <height_h_plus_1> <contract_addr> <storage_key_hex>

# Verify offline
proofs verify-receipt <submission_json_file>
proofs verify-storage <submission_json_file>
```

Examples:

```bash
proofs receipt https://api.calibration.node.glif.io/rpc/v1 123456 bafy2bzace...
proofs storage https://api.calibration.node.glif.io/rpc/v1 123456 0xabc...def 0x01...
```

### Output schema

Receipt submission JSON matches `types::ReceiptSubmission`:

```json
{
  "f3_cert": "<base64-bytes>",
  "header": { "cid": "<cid>", "raw": "<bytes>" },
  "amt": {
    "root": "<cid>",
    "index": 0,
    "nodes": [{ "cid": "<cid>", "raw": "<bytes>" }],
    "leaf": { "ExitCode": 0, "GasUsed": 0, "Return": "<bytes>" }
  }
}
```

Storage submission matches `types::StorageSubmission`.

### Notes

- F3 certificate is mocked and accepted by the verifier.
- Dependencies are pinned to versions compatible with Lotus APIs as of 2025-08.
