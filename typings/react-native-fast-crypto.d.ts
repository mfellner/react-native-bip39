declare module 'react-native-fast-crypto' {
  const crypto: Crypto;

  interface Crypto {
    pbkdf2: {
      deriveAsync(
        data: Uint8Array,
        salt: Uint8Array,
        iterations: number,
        size: number,
        alg: string,
      ): Promise<Uint8Array>;
    };
  }

  export = crypto;
}
