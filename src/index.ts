import { PallierEncryption } from "./pallier";

const paillier = new PallierEncryption(); // Slow!
const keys = { pub: paillier.pub, priv: paillier.priv };
const plaintext1 = 1234567890n;
const plaintext2 = 55555555555n;

console.log(keys);

const ciphertext1 = paillier.encrypt(keys.pub)(plaintext1);
const ciphertext2 = paillier.encrypt(keys.pub)(plaintext2);

const ciphertextSum = paillier.add(keys.pub)(ciphertext1, ciphertext2);
const plaintextSum = paillier.decrypt(keys)(ciphertextSum); // 56790123445n = plaintext1 + plaintext2

const ciphertextProduct = paillier.multiply(keys.pub)(ciphertext1, plaintext2);
const plaintextProduct = paillier.decrypt(keys)(ciphertextProduct); // 68587104999314128950n = plaintext1 * plaintext2

console.log(ciphertext1, ciphertext2, ciphertextSum);
