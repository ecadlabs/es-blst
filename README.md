# ES-blst
ES and TypeScript wrapper around Wasm-built [blst](https://github.com/supranational/blst) BLS12-381 signature library.

## Requirements
ES2022 environment for asynchronous instantiating of the Wasm module during loading.

## Build

### Prerequisites
Clang >= 9.0 with `wasm32` target available

#### MacOS
By default Homebrew doesn't link LLVM executables into its global executables directory which is usually listed in PATH.
To build on MacOS you have to add LLVM directory (usually `/opt/homebrew/opt/llvm/bin` or `/usr/local/opt/llvm/bin`
depending on Homebrew version) to PATH:

```sh
export PATH="/opt/homebrew/opt/llvm/bin:${PATH}"
```

The exact path will be printed after LLVM installation is finished.

### Building
```sh
npm run init && npm run build
```

## Example

```typescript
import { MinPk } from "es-blst";

// generate a private key
const ikm = new Uint8Array(32);
crypto.getRandomValues(ikm);
const priv = MinPk.PrivateKey.generate(ikm);

// sign a message
const msg = new TextEncoder().encode("message text");
const sig = priv.sign(msg, "aug");

// derive a public key
const pub = priv.public();

// verify
const ok = sig.verify("aug", pub, msg);
console.log(ok);
```