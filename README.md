# ES-blst
ES and TypeScript wrapper around Wasm-built [blst](https://github.com/supranational/blst) BLS12-381 signature library.

## Requirements
ES2022 environment for asynchronous instantiating of the Wasm module during loading.

## Build

### Prerequisites
clang >= 9.0 installed in the search path or in `/opt/homebrew/opt/llvm/bin`

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