import { Blst, getSuite, type Scheme, type PkMsgPair } from "./blst.js";

export class PrivateKey {
    private constructor(private readonly scalar: Uint8Array) { }

    static generate(ikm: Uint8Array): PrivateKey {
        return new PrivateKey(Blst.keygen(ikm));
    }

    static fromBytes(bytes: Uint8Array): PrivateKey {
        return new PrivateKey(Blst.scalar_from_lendian(bytes));
    }

    bytes(): Uint8Array {
        return Blst.lendian_from_scalar(this.scalar);
    }

    public(): PublicKey {
        return PublicKey.fromPoint(Blst.sk_to_pk2_in_g2(this.scalar));
    }

    sign(msg: Uint8Array, scheme: Scheme): Signature {
        const aug = scheme === "aug" ? this.public().bytes() : undefined;
        const q = Blst.hash_to_g1(msg, getSuite(scheme, 1), aug);
        return Signature.fromPoint(Blst.sign_pk2_in_g2(q, this.scalar));
    }
}

export class PublicKey {
    private constructor(public readonly _point: Uint8Array) { }

    static fromBytes(bytes: Uint8Array): PublicKey {
        return new PublicKey(Blst.p2_uncompress(bytes));
    }

    static fromPoint(point: Uint8Array): PublicKey {
        return new PublicKey(point);
    }

    bytes(): Uint8Array {
        return Blst.p2_affine_compress(this._point);
    }

    valid(): boolean {
        return !Blst.p2_affine_is_inf(this._point) && Blst.p2_affine_in_g2(this._point);
    }

    onCurve(): boolean {
        return Blst.p2_affine_on_curve(this._point);
    }

    equal(other: PublicKey): boolean {
        return Blst.p2_affine_is_equal(this._point, other._point);
    }
}

export class Signature {
    private constructor(private readonly point: Uint8Array) { }

    static fromBytes(bytes: Uint8Array): Signature {
        return new Signature(Blst.p1_uncompress(bytes));
    }

    static fromPoint(point: Uint8Array): Signature {
        return new Signature(point);
    }

    bytes(): Uint8Array {
        return Blst.p1_affine_compress(this.point);
    }

    aggregateVerify(scheme: Scheme, ...pairs: [PublicKey, Uint8Array][]): boolean {
        const verifyPairs = pairs.map<PkMsgPair>(([pk, msg]) => ({
            pk: pk._point,
            msg,
            aug: scheme === "aug" ? pk.bytes() : undefined
        }));
        return Blst.core_aggregate_verify_g2(this.point, true, verifyPairs, true, true, getSuite(scheme, 1));
    }

    verify(scheme: Scheme, pk: PublicKey, msg: Uint8Array): boolean {
        const aug = scheme === "aug" ? pk.bytes() : undefined;
        return Blst.core_verify_pk_in_g2(pk._point, this.point, true, msg, getSuite(scheme, 1), aug);
    }

    valid(groupCheck: boolean = false): boolean {
        return !Blst.p1_affine_is_inf(this.point) && (!groupCheck || Blst.p1_affine_in_g1(this.point));
    }

    onCurve(): boolean {
        return Blst.p1_affine_on_curve(this.point);
    }

    equal(other: Signature): boolean {
        return Blst.p1_affine_is_equal(this.point, other.point);
    }
}
