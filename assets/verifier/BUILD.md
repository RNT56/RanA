# Building the export verifier viewer

This directory (`assets/verifier/`) is the self-contained, offline HTML
viewer for `docs/TRUST.md §8`'s independent export verification, described
in `cmd/rana-verify-wasm`'s package doc comment.

`index.html`, `main.js`, and `style.css` are checked in. Two files are
**build artifacts, not checked in**, and must be produced before the page
will load:

```sh
# 1. The WebAssembly binary itself.
GOOS=js GOARCH=wasm go build -o assets/verifier/rana-verify.wasm ./cmd/rana-verify-wasm

# 2. Go's JS support shim, copied from the toolchain that built it.
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" assets/verifier/wasm_exec.js
# (older Go toolchains: "$(go env GOROOT)/misc/wasm/wasm_exec.js")
```

The release pipeline runs both steps and bundles the resulting five files
(`index.html`, `main.js`, `style.css`, `rana-verify.wasm`, `wasm_exec.js`)
together — the page is fully self-contained and works with `file://` or any
static file server, with **no build step required by the end user** and
**no network access at runtime** (D24): every fetch it performs is
same-origin, for these five files only.

To try it locally:

```sh
GOOS=js GOARCH=wasm go build -o assets/verifier/rana-verify.wasm ./cmd/rana-verify-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" assets/verifier/wasm_exec.js
python3 -m http.server 8000 --directory assets/verifier
# open http://localhost:8000/
```

Then drop an export directory's files (`manifest.json`, `events.cbor`,
`segments.cbor`, `checkpoints.cbor`, `pubkey.pem` — `docs/TRUST.md §7`) onto
the page and click "Verify export".
