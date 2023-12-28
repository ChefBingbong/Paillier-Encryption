import { lcm, modInv, modPow, primeSync, randBetween } from "bigint-crypto-utils";
import { getBitLength } from "./utils";
import { KeyPair, PrivateKey, PublicKey } from "./types";

export class PallierEncryption {
      public pub: PublicKey | undefined;
      public priv: PrivateKey | undefined;

      public p: bigint | undefined;
      public q: bigint | undefined;
      public isInitialized: boolean = false;

      constructor() {
            this.generateKeysSync();
            this.isInitialized = true;
      }

      public encrypt = (plainText: bigint): bigint => {
            if (!this.isInitialized)
                  throw new Error(`Pub/Priv keys havent been generated yet`);
            const { n, n2, g } = this.pub;
            const r = randBetween(n);
            return (modPow(g, plainText, n2) * modPow(r, n, n2)) % n2;
      };

      public decrypt = (cipherText: bigint): bigint => {
            if (!this.isInitialized)
                  throw new Error(`Pub/Priv keys havent been generated yet`);
            const { lambda, mu } = this.priv;
            const { n, n2 } = this.pub;
            const L = this.computeDecryptionShift(n);
            return (L(modPow(cipherText, lambda, n2)) * mu) % n;
      };

      public add = (a: bigint, b: bigint): bigint => (a * b) % this.pub.n2;

      public multiply = (cipherText: bigint, plainText: bigint): bigint => {
            if (!this.isInitialized)
                  throw new Error(`Pub/Priv keys havent been generated yet`);
            if (plainText === 0n) {
                  return this.encrypt(0n);
            }
            if (plainText === 1n) {
                  const encryptedZero = this.encrypt(0n);
                  return this.add(cipherText, encryptedZero);
            }
            return modPow(cipherText, plainText, this.pub.n2);
      };

      public getKeys = (p: bigint, q: bigint, n: bigint, g: bigint): KeyPair => {
            const n2 = n ** 2n;
            const lambda = this.calculateLambda(p, q);
            const mu = this.calculateDecryptionCoefficient(g, lambda, n, n2);

            if (!mu) {
                  throw new Error("mu does not exist");
            }

            this.pub = { n, n2, g };
            this.priv = { lambda, mu };
            return { pub: this.pub, priv: this.priv };
      };

      private generateGenerator = (n: bigint, n2 = n ** 2n): bigint => {
            const alpha = randBetween(n);
            const beta = randBetween(n);
            return ((alpha * n + 1n) * modPow(beta, n, n2)) % n2;
      };

      private generateKeysSync = (bitLength = 3072): KeyPair => {
            const halfBitLength = Math.floor(bitLength / 2);
            this.p = primeSync(halfBitLength + 1);
            this.q = primeSync(halfBitLength);
            const n = this.p * this.q;

            if (this.p === this.q || getBitLength(n) !== bitLength) {
                  return this.generateKeysSync(bitLength);
            }

            const g = this.generateGenerator(n);
            try {
                  return this.getKeys(this.p, this.q, n, g);
            } catch (error) {
                  if (/mu does not exist/i.test(error as any)) {
                        return this.generateKeysSync(bitLength);
                  }
                  throw error;
            }
      };

      public computeDecryptionShift =
            (n: bigint) =>
            (x: bigint): bigint =>
                  (x - 1n) / n;

      public calculateDecryptionCoefficient = (
            g: bigint,
            lambda: bigint,
            n: bigint,
            n2 = n ** 2n
      ): bigint => {
            const L = this.computeDecryptionShift(n);
            return modInv(L(modPow(g, lambda, n2)), n);
      };

      public calculateLambda = (p: bigint, q: bigint): bigint => lcm(p - 1n, q - 1n);
}
