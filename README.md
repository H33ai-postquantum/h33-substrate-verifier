# H33-74 Standalone Verifier

Offline verification of H33-74 post-quantum attestations. No API key. No network calls. Pure cryptographic verification.

## What this verifies

Every H33-74 attestation is a 58-byte substrate signed with three independent post-quantum signature families:

- **ML-DSA-65** (FIPS 204) — MLWE lattice, NIST Level 3
- **FALCON-512** (Draft FIPS 206) — NTRU lattice, Level 1
- **SLH-DSA-SHA2-128f** (FIPS 205) — Hash-based, Level 1

Forgery requires breaking all three simultaneously — three independent mathematical hardness assumptions.

## Build

```bash
cargo build --release
```

## Usage

### Batch verification (JSON vector file)

```bash
./target/release/h33-74-verifier vectors.json
```

### Single attestation verification

```bash
./target/release/h33-74-verifier \
  --substrate <58-byte-hex> \
  --sig <ml-dsa-65-signature-hex> \
  --pk <ml-dsa-65-public-key-hex>
```

## Substrate layout

```
[0]       version            (1 byte, always 0x01)
[1]       computation_type   (1 byte, domain separator)
[2..34]   fhe_commitment     (32 bytes, SHA3-256 of FHE output)
[34..42]  timestamp_ms       (8 bytes, big-endian millisecond Unix)
[42..58]  nonce              (16 bytes, random anti-replay)
```

The signing message is `SHA3-256(substrate_bytes)` — always exactly 32 bytes.

## License

MIT

## About

Built by [H33.ai](https://h33.ai). 7 patents pending, 250+ claims. Post-quantum cryptographic infrastructure.

## Quick test

The repo includes `vectors.json` with 10 production test vectors (6 valid + 4 adversarial):

```bash
cargo build --release
./target/release/h33-74-verifier vectors.json
```

Expected output: 10 passed, 0 failed.
