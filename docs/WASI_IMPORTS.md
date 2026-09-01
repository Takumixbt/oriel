# WASI import snapshot

The release component was inspected with `wasm-tools component wit` after each
release build. The authored T3N imports are:

```text
host:tenant/tenant-context@1.0.0
host:interfaces/logging@2.1.0
host:interfaces/kv-store@2.1.0
host:interfaces/http@2.1.0
```

`wit-bindgen` also emits the following standard WASI support imports for the
component runtime. They are expected and are not additional application data
permissions:

```text
wasi:io/poll@0.2.9
wasi:clocks/monotonic-clock@0.2.9
wasi:io/error@0.2.9
wasi:io/streams@0.2.9
wasi:cli/stdout@0.2.9
wasi:cli/stderr@0.2.9
wasi:cli/stdin@0.2.9
wasi:cli/environment@0.2.9
wasi:cli/exit@0.2.9
wasi:cli/terminal-input@0.2.9
wasi:cli/terminal-output@0.2.9
wasi:cli/terminal-stdin@0.2.9
wasi:cli/terminal-stdout@0.2.9
wasi:cli/terminal-stderr@0.2.9
```

CI validates the artifact. A future platform hardening step should compare the
full generated import set against this snapshot and fail if a new non-WASI
import appears.
