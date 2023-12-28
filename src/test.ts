import { PallierEncryption } from "./pallier";

describe("add", () => {
      const paillier = new PallierEncryption();
      const encryptN = paillier.encrypt(paillier.pub);
      const decryptN = paillier.decrypt({ priv: paillier.priv, pub: paillier.pub });

      it("adds two encrypted numbers", () => {
            const a = 123n;
            const b = 456n;
            const expected = 579n;

            const cipherTextA = encryptN(a);
            const cipherTextB = encryptN(b);

            const encryptedResult = paillier.add(paillier.pub)(
                  cipherTextA,
                  cipherTextB
            );
            const result = decryptN(encryptedResult);
            expect(result).toStrictEqual(expected);
      });
});

describe("multiply", () => {
      const paillier = new PallierEncryption();

      const encryptN = paillier.encrypt(paillier.pub);
      const decryptN = paillier.decrypt({ priv: paillier.priv, pub: paillier.pub });
      const multiplyForPublicKey = paillier.multiply(paillier.pub);

      it("multiplies an encrypted number by an unencrypted number", () => {
            const a = 123n;
            const b = 456n;
            const expected = 56088n;

            const cipherText = encryptN(a);

            const encryptedResult = multiplyForPublicKey(cipherText, b);
            const result = decryptN(encryptedResult);

            expect(result).toStrictEqual(expected);
      });

      it("multiplies by 0 securely", () => {
            const a = 123n;
            const b = 0n;

            const cipherText = encryptN(a);
            const naiveEncryptedResult = 1n;

            const encryptedResult = multiplyForPublicKey(cipherText, b);

            expect(encryptedResult).not.toStrictEqual(naiveEncryptedResult);
      });

      it("multiplies by 1 securely", () => {
            const a = 123n;
            const b = 1n;

            const cipherText = encryptN(a);
            const naiveEncryptedResult = cipherText;

            const encryptedResult = multiplyForPublicKey(cipherText, b);

            expect(encryptedResult).not.toStrictEqual(naiveEncryptedResult);
      });
});
