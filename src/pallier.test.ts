import { PallierEncryption } from "./pallier";

describe("add", () => {
      const paillier = new PallierEncryption();
      const encryptN = paillier.encrypt;
      const decryptN = paillier.decrypt;

      it("adds two encrypted numbers", () => {
            const a = 123n;
            const b = 456n;
            const expected = 579n;

            const cipherTextA = encryptN(a);
            const cipherTextB = encryptN(b);

            const encryptedResult = paillier.add(cipherTextA, cipherTextB);
            const result = decryptN(encryptedResult);
            expect(result).toStrictEqual(expected);
      });
});

describe("multiply", () => {
      const paillier = new PallierEncryption();

      const encryptN = paillier.encrypt;
      const decryptN = paillier.decrypt;

      it("multiplies an encrypted number by an unencrypted number", () => {
            const a = 123n;
            const b = 456n;
            const expected = 56088n;

            const cipherText = encryptN(a);

            const encryptedResult = paillier.multiply(cipherText, b);
            const result = decryptN(encryptedResult);

            expect(result).toStrictEqual(expected);
      });

      it("multiplies by 0 securely", () => {
            const a = 123n;
            const b = 0n;

            const cipherText = encryptN(a);
            const naiveEncryptedResult = 1n;

            const encryptedResult = paillier.multiply(cipherText, b);

            expect(encryptedResult).not.toStrictEqual(naiveEncryptedResult);
      });

      it("multiplies by 1 securely", () => {
            const a = 123n;
            const b = 1n;

            const cipherText = encryptN(a);
            const naiveEncryptedResult = cipherText;

            const encryptedResult = paillier.multiply(cipherText, b);

            expect(encryptedResult).not.toStrictEqual(naiveEncryptedResult);
      });
});

describe("getKeys", () => {
      const p = 17n;
      const q = 19n;
      const n = 323n;
      const lambda = 144n;
      const g = 848n;
      const mu = 1n;
      const paillier = new PallierEncryption();

      describe("with provided p, q, n, and g", () => {
            const keys = paillier.getKeys(p, q, n, g);

            it("generates public key", () => {
                  expect(keys.pub.n).toStrictEqual(n);
                  expect(keys.pub.n2).toStrictEqual(n ** 2n);
                  expect(keys.pub.g).toStrictEqual(g);
            });

            it("generates private key", () => {
                  expect(keys.priv.lambda).toStrictEqual(lambda);
                  expect(keys.priv.mu).toStrictEqual(mu);
            });
      });
});

describe("createL", () => {
      const n = 15n;
      const paillier = new PallierEncryption();

      const L = paillier.computeDecryptionShift(n);

      test("creates a function", () => {
            expect(typeof L).toBe("function");
      });

      test("created function implements L", () => {
            const x = 136n;
            const expected = 9n;
            const actual = L(x);
            expect(actual).toStrictEqual(expected);
      });
});

describe("calculateMu", () => {
      const paillier = new PallierEncryption();

      test("calculates mu", () => {
            const g = 848n;
            const lambda = 144n;
            const n = 323n;
            const expected = 1n;
            const actual = paillier.calculateDecryptionCoefficient(g, lambda, n);
            expect(actual).toStrictEqual(expected);
      });
});

describe("encrypt and decrypt", () => {
      const paillier = new PallierEncryption();

      const plainText = 19134702400093278081449423917n;
      const alternativePlainText = 19134702400093278081449423916n;

      it("encrypts a plain text", () => {
            const cipherText = paillier.encrypt(plainText);
            expect(cipherText).not.toStrictEqual(plainText);
      });

      it("encrypts a plain text differently each time", () => {
            const cipherText1 = paillier.encrypt(plainText);
            const cipherText2 = paillier.encrypt(plainText);
            expect(cipherText1).not.toStrictEqual(cipherText2);
      });

      it("encrypts two different plain texts differently", () => {
            const cipherText1 = paillier.encrypt(plainText);
            const cipherText2 = paillier.encrypt(alternativePlainText);
            expect(cipherText1).not.toStrictEqual(cipherText2);
      });

      it("encrypts a plain text and decrypts to the original", () => {
            const cipherText = paillier.encrypt(plainText);
            const decrypted = paillier.decrypt(cipherText);
            expect(decrypted).toStrictEqual(plainText);
      });
});
