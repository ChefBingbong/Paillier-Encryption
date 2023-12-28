import { lcm, modInv, modPow, primeSync, randBetween } from "bigint-crypto-utils";
import { getBitLength } from "./utils";

export type PublicKey = {
      readonly n: bigint;
      readonly n2: bigint;
      readonly g: bigint;
};

export type PrivateKey = {
      readonly lambda: bigint;
      readonly mu: bigint;
};

export type KeyPair = {
      readonly pub: PublicKey;
      readonly priv: PrivateKey;
};

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

      public encrypt =
            ({ g, n, n2 }: PublicKey) =>
            (plainText: bigint): bigint => {
                  if (!this.isInitialized)
                        throw new Error(`Pub/Priv keys havent been generated yet`);
                  const r = randBetween(n);
                  return (modPow(g, plainText, n2) * modPow(r, n, n2)) % n2;
            };

      public decrypt =
            ({ priv: { lambda, mu }, pub: { n, n2 } }: KeyPair) =>
            (cipherText: bigint): bigint => {
                  if (!this.isInitialized)
                        throw new Error(`Pub/Priv keys havent been generated yet`);
                  const L = this.computeDecryptionShift(n);
                  return (L(modPow(cipherText, lambda, n2)) * mu) % n;
            };

      public add =
            ({ n2 }: PublicKey) =>
            (a: bigint, b: bigint): bigint =>
                  (a * b) % n2;

      public multiply =
            (publicKey: PublicKey) =>
            (cipherText: bigint, plainText: bigint): bigint => {
                  if (!this.isInitialized)
                        throw new Error(`Pub/Priv keys havent been generated yet`);
                  if (plainText === 0n) {
                        return this.encrypt(publicKey)(0n);
                  }
                  if (plainText === 1n) {
                        const encryptedZero = this.encrypt(publicKey)(0n);
                        return this.add(publicKey)(cipherText, encryptedZero);
                  }
                  return modPow(cipherText, plainText, publicKey.n2);
            };

      private getKeys = (p: bigint, q: bigint, n: bigint, g: bigint): KeyPair => {
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

      // Adapted from https://github.com/juanelas/paillier-bigint/blob/904164e/src/js/index.js#L98-L102
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

      private computeDecryptionShift =
            (n: bigint) =>
            (x: bigint): bigint =>
                  (x - 1n) / n;

      private calculateDecryptionCoefficient = (
            g: bigint,
            lambda: bigint,
            n: bigint,
            n2 = n ** 2n
      ): bigint => {
            const L = this.computeDecryptionShift(n);
            return modInv(L(modPow(g, lambda, n2)), n);
      };

      private calculateLambda = (p: bigint, q: bigint): bigint =>
            lcm(p - 1n, q - 1n);
}
