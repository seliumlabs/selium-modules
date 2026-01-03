# Atlas

The atlas is a directory service for discovering resources.

## Crate structure

This service has 3 crates:
- `selium-atlas` (_client/_) - client library that guests consume
- `selium-atlas-protocol` (_protocol/_) - wire protocol
- `selium-atlas-server` (_server/_) - WASM module run by the host
