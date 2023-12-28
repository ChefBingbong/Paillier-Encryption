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
