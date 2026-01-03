# Switchboard

The switchboard service provides an orchestration layer on top of core I/O. It provides realtime rationalising of channel infrastructure as the environment changes (e.g. a new subscriber being created, or a service being shut down), as well as a more ergonomic messaging library.

## Crate structure

This service has 4 crates:
- `selium-switchboard` (_client/_) - client library that guests consume
- `selium-switchboard-core` (_core/_) - core logic
- `selium-switchboard-protocol` (_protocol/_) - wire protocol
- `selium-switchboard-server` (_server/_) - WASM module run by the host
