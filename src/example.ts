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
