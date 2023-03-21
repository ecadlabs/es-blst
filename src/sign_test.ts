import { assert } from "chai";
import { MinPk, MinSig, Scheme } from "./index.js";
import { run } from "./testing.js";
import * as fs from "node:fs";
import * as readline from "node:readline";
import * as path from "node:path";
import * as crypto from "node:crypto";

let status;

async function getRecords(fname: string): Promise<Uint8Array[][]> {
  const rl = readline.createInterface({
    input: fs.createReadStream(fname)
  });

  const out: Uint8Array[][] = [];
  for await (const line of rl) {
    const f = line.split(" ");
    const rec = f.map((x) => new Uint8Array(Buffer.from(x, "hex")));
    out.push(rec);
  }
  return out;
}

interface TestCase {
  group: string;
  scheme: Scheme;
  files: string[];
}

async function start() {
  status = await run(null, async (ctx) => {
    await run("minpk", async (ctx) => {
      await run("encode", async () => {
        const ikm = new Uint8Array(crypto.randomBytes(32));

        const sk = MinPk.PrivateKey.generate(ikm);
        const encSk = sk.bytes();
        assert.equal(encSk.length, MinPk.PrivateKey.ByteLength);

        const decSk = MinPk.PrivateKey.fromBytes(encSk);
        assert.deepEqual(decSk, sk);

        const pk = sk.public();
        const encPk = pk.bytes();
        assert.equal(encPk.length, MinPk.PublicKey.ByteLength);
        const decPk = MinPk.PublicKey.fromBytes(encPk);
        assert.equal(decPk.equal(pk), true);
      }, ctx);

      const cases: TestCase[] = [
        {
          group: "sig_g2_basic",
          scheme: "basic",
          files: [
            "sig_g2_basic_fips_186_3_B233_blst",
            "sig_g2_basic_fips_186_3_B283_blst",
            "sig_g2_basic_fips_186_3_B409_blst",
            "sig_g2_basic_fips_186_3_B571_blst",
            "sig_g2_basic_fips_186_3_K233_blst",
            "sig_g2_basic_fips_186_3_K409_blst",
            "sig_g2_basic_fips_186_3_K571_blst",
            "sig_g2_basic_fips_186_3_P224_blst",
            "sig_g2_basic_fips_186_3_P256_blst",
            "sig_g2_basic_fips_186_3_P384_blst",
            "sig_g2_basic_fips_186_3_P521_blst",
            "sig_g2_basic_rfc6979_blst"
          ]
        },
        {
          group: "sig_g2_aug",
          scheme: "aug",
          files: [
            "sig_g2_aug_fips_186_3_B233_blst",
            "sig_g2_aug_fips_186_3_B283_blst",
            "sig_g2_aug_fips_186_3_B409_blst",
            "sig_g2_aug_fips_186_3_B571_blst",
            "sig_g2_aug_fips_186_3_K233_blst",
            "sig_g2_aug_fips_186_3_K409_blst",
            "sig_g2_aug_fips_186_3_K571_blst",
            "sig_g2_aug_fips_186_3_P224_blst",
            "sig_g2_aug_fips_186_3_P256_blst",
            "sig_g2_aug_fips_186_3_P384_blst",
            "sig_g2_aug_fips_186_3_P521_blst",
            "sig_g2_aug_rfc6979_blst"
          ]
        }
      ];

      for (const group of cases) {
        await run(group.group, async (ctx) => {
          for (const file of group.files) {
            await run(file, async () => {
              const records = await getRecords(path.resolve("./vectors", group.group, file));
              for (const rec of records) {
                const [msg, ikm, result] = rec;
                if (ikm.length < 32) {
                  continue;
                }
                const priv = MinPk.PrivateKey.generate(ikm);
                const sig = priv.sign(msg, group.scheme);
                assert.strictEqual(sig.valid(true), true, "invalid signature");
                assert.deepEqual(sig.bytes(), result, "signatures are not equal");

                const pub = priv.public();
                assert.strictEqual(pub.valid(), true, "invalid pubkey");

                const res = sig.verify(group.scheme, pub, msg);
                assert.strictEqual(res, true, "verify failed");

                const res1 = sig.aggregateVerify(group.scheme, [[pub, msg]]);
                assert.strictEqual(res1, true, "aggregate verify failed");
              }
            }, ctx);
          }
        }, ctx);
      }

      await run("aggregate", async () => {
        const numSig = 4;
        const pairs: [MinPk.PublicKey, Uint8Array][] = [];
        const sigs: MinPk.Signature[] = [];

        for (let i = 0; i < numSig; i++) {
          const ikm = new Uint8Array(crypto.randomBytes(32));
          const msg = new Uint8Array(crypto.randomBytes(32));

          const sk = MinPk.PrivateKey.generate(ikm);
          const sig = sk.sign(msg, "basic");
          const pk = sk.public();
          sigs.push(sig);
          pairs.push([pk, msg]);
        }

        const aggregated = MinPk.aggregateSignatures(...sigs);
        assert.strictEqual(aggregated.aggregateVerify("basic", pairs), true, "aggregate verify failed");
      }, ctx);
    }, ctx);

    await run("minsig", async (ctx) => {
      await run("encode", async () => {
        const ikm = new Uint8Array(crypto.randomBytes(32));

        const sk = MinSig.PrivateKey.generate(ikm);
        const encSk = sk.bytes();
        assert.equal(encSk.length, MinSig.PrivateKey.ByteLength);

        const decSk = MinSig.PrivateKey.fromBytes(encSk);
        assert.deepEqual(decSk, sk);

        const pk = sk.public();
        const encPk = pk.bytes();
        assert.equal(encPk.length, MinSig.PublicKey.ByteLength);
        const decPk = MinSig.PublicKey.fromBytes(encPk);
        assert.equal(decPk.equal(pk), true);
      }, ctx);

      const cases: TestCase[] = [
        {
          group: "sig_g1_basic",
          scheme: "basic",
          files: [
            "sig_g1_basic_fips_186_3_B233_blst",
            "sig_g1_basic_fips_186_3_B283_blst",
            "sig_g1_basic_fips_186_3_B409_blst",
            "sig_g1_basic_fips_186_3_B571_blst",
            "sig_g1_basic_fips_186_3_K233_blst",
            "sig_g1_basic_fips_186_3_K409_blst",
            "sig_g1_basic_fips_186_3_K571_blst",
            "sig_g1_basic_fips_186_3_P224_blst",
            "sig_g1_basic_fips_186_3_P256_blst",
            "sig_g1_basic_fips_186_3_P384_blst",
            "sig_g1_basic_fips_186_3_P521_blst",
            "sig_g1_basic_rfc6979_blst"
          ]
        },
        {
          group: "sig_g1_aug",
          scheme: "aug",
          files: [
            "sig_g1_aug_fips_186_3_B233_blst",
            "sig_g1_aug_fips_186_3_B283_blst",
            "sig_g1_aug_fips_186_3_B409_blst",
            "sig_g1_aug_fips_186_3_B571_blst",
            "sig_g1_aug_fips_186_3_K233_blst",
            "sig_g1_aug_fips_186_3_K409_blst",
            "sig_g1_aug_fips_186_3_K571_blst",
            "sig_g1_aug_fips_186_3_P224_blst",
            "sig_g1_aug_fips_186_3_P256_blst",
            "sig_g1_aug_fips_186_3_P384_blst",
            "sig_g1_aug_fips_186_3_P521_blst",
            "sig_g1_aug_rfc6979_blst"
          ]
        }
      ];

      for (const group of cases) {
        await run(group.group, async (ctx) => {
          for (const file of group.files) {
            await run(file, async () => {
              const records = await getRecords(path.resolve("./vectors", group.group, file));
              for (const rec of records) {
                const [msg, ikm, result] = rec;
                if (ikm.length < 32) {
                  continue;
                }
                const priv = MinSig.PrivateKey.generate(ikm);
                const sig = priv.sign(msg, group.scheme);
                assert.strictEqual(sig.valid(true), true, "invalid signature");
                assert.deepEqual(sig.bytes(), result, "signatures are not equal");

                const pub = priv.public();
                assert.strictEqual(pub.valid(), true, "invalid pubkey");

                const res = sig.verify(group.scheme, pub, msg);
                assert.strictEqual(res, true, "verify failed");

                const res1 = sig.aggregateVerify(group.scheme, [[pub, msg]]);
                assert.strictEqual(res1, true, "aggregate verify failed");
              }
            }, ctx);
          }
        }, ctx);
      }

      await run("aggregate", async () => {
        const numSig = 4;
        const pairs: [MinSig.PublicKey, Uint8Array][] = [];
        const sigs: MinSig.Signature[] = [];

        for (let i = 0; i < numSig; i++) {
          const ikm = new Uint8Array(crypto.randomBytes(32));
          const msg = new Uint8Array(crypto.randomBytes(32));

          const sk = MinSig.PrivateKey.generate(ikm);
          const sig = sk.sign(msg, "basic");
          const pk = sk.public();
          sigs.push(sig);
          pairs.push([pk, msg]);
        }

        const aggregated = MinSig.aggregateSignatures(...sigs);
        assert.strictEqual(aggregated.aggregateVerify("basic", pairs), true, "aggregate verify failed");
      }, ctx);
    }, ctx);
  });
  return status;
}

let result;

(async () => {
  try {
    result = await start();
  } catch (e) {
    console.log(e);
  }
})();


process.exit(result ? 0 : 1);
