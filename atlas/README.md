# Atlas

The atlas is a directory service for discovering resources.

## Crate structure

This service has 3 crates:
- `selium-atlas` (_client/_) - client library that guests consume
- `selium-atlas-protocol` (_protocol/_) - wire protocol
- `selium-atlas-server` (_server/_) - WASM module run by the host

## Usage

Compile the `selium-atlas-server` component to WebAssembly and install in the Runtime's work directory:

```bash
cargo build --release --target wasm32-unknown-unknown -p selium-atlas-server
cp target/wasm32-unknown-unknown/release/selium_atlas_server.wasm /path/to/selium-runtime/work/modules/
```

The `selium-atlas-server` component should be added to the Selium Runtime's initialisation args:

```bash
selium-runtime \
  --work-dir /path/to/selium-runtime/work \
  --module "path=selium_atlas_server.wasm;capabilities=ChannelLifecycle,ChannelReader,ChannelWriter"
```
