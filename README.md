# CARROT Hybrid Key Schedule Demo

Small isolated demonstration of the hybrid key-derivation idea I use as part of CARROT.

This is not the CARROT transport protocol. The labels and domain in this repo are portfolio demonstration values, not the unreleased transport schedule.

Current features include

- X25519 shared-secret agreement in the host example
- ML-KEM-768 shared-secret agreement in the host example
- HKDF-SHA-256 hybrid key derivation
- separate initiator and responder keys
- separate nonces and a transcript key
- zeroization of temporary secret material
- `no_std` library code

## Run

```text
cargo test
cargo run --example host_exchange
```

CARROT and this demonstration are unaudited. Do not use this as a transport or for sensitive operations.

Released under the included CARROT study-only source license. Read `LICENSE` before using or redistributing it.
