# Remote Client module

Provides users with a client library and CLI for orchestrating Selium applications and servers from afar.

## Crate structure

This service has 4 crates:
- `selium-remote-client-cli` (_cli/_) - CLI binary for executing commands via the `selium-remote-client` lib
- `selium-remote-client` (_client/_) - client library that guests consume
- `selium-remote-client-protocol` (_protocol/_) - wire protocol
- `selium-remote-client-server` (_server/_) - WASM module run by the host

## Usage

Compile the `selium-remote-client-server` component to WebAssembly and install in the Runtime's work directory:

```bash
cargo build --release --target wasm32-unknown-unknown -p selium-remote-client-server
cp target/wasm32-unknown-unknown/release/selium_remote_client_server.wasm /path/to/selium-runtime/work/modules/
```

The `selium-remote-client-server` component should be added to the Selium Runtime's initialisation args:

```bash
selium-runtime \
  --work-dir /path/to/selium-runtime/work \
  --module "path=selium_remote_client_server.wasm;capabilities=ChannelLifecycle,ChannelReader,ChannelWriter,ProcessLifecycle,NetBind,NetAccept,NetRead,NetWrite;args=utf8:localhost,u16:7000"
```
