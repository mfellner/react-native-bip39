import { Buffer } from 'buffer';
import { pbkdf2 as mockPbkdf2, randomBytes as mockRandomBytes } from 'crypto';
import * as bip39 from '../src/';
import DEFAULT_WORDLIST from '../wordlists/en.json';
import vectors from './vectors.json';
import CUSTOM_WORDLIST from './wordlist.json';

const mockGenerateSecureRandomAsBase64 = jest.fn(async (length: number) =>
  mockRandomBytes(length).toString('base64'),
);

const mockBuffer = Buffer;

jest.mock('react-native', () => ({
  NativeModules: {
    RNSecureRandom: {
      generateSecureRandomAsBase64: (length: number) => mockGenerateSecureRandomAsBase64(length),
    },
    RNFastCrypto: {
      pbkdf2Sha512: jest.fn((data: string, salt: string, iterations: number, size: number) => {
        return new Promise((resolve, reject) => {
          mockPbkdf2(
            mockBuffer.from(data, 'base64'),
            mockBuffer.from(salt, 'base64'),
            iterations,
            size,
            'sha512',
            (err, derivedKey) => {
              if (err) return reject(err);
              resolve(derivedKey.toString('base64'));
            },
          );
        });
      }),
    },
  },
}));

test.each([
  ...vectors.english.map((v, i) => ['English', undefined, 'TREZOR', v, i] as const),
  ...vectors.japanese.map(
    (v, i) => ['Japanese', bip39.wordlists.JA, '㍍ガバヴァぱばぐゞちぢ十人十色', v, i] as const,
  ),
  ...vectors.custom.map((v, i) => ['Custom', CUSTOM_WORDLIST, undefined, v, i] as const),
])('for %s test vector %#', async (description, wordlist, password, v, i) => {
  const ventropy = v[0];
  const vmnemonic = v[1];
  const vseedHex = v[2];

  expect(bip39.mnemonicToEntropy(vmnemonic, wordlist)).toEqual(ventropy);
  // TODO FIXME
  expect(await bip39.mnemonicToSeedHex(vmnemonic, password)).toEqual(vseedHex);

  expect(bip39.entropyToMnemonic(ventropy, wordlist)).toEqual(vmnemonic);

  const rng = async () => Buffer.from(ventropy, 'hex');

  expect(await bip39.generateMnemonic(undefined, rng, wordlist)).toEqual(vmnemonic);
  expect(bip39.validateMnemonic(vmnemonic, wordlist)).toBe(true);
});

test.each(vectors.japanese)('UTF8 passwords', async (ventropy, vmnemonic, vseedHex) => {
  const password = '㍍ガバヴァぱばぐゞちぢ十人十色';
  const normalizedPassword = 'メートルガバヴァぱばぐゞちぢ十人十色';

  expect(await bip39.mnemonicToSeedHex(vmnemonic, password)).toEqual(vseedHex); // 'mnemonicToSeedHex normalizes passwords',

  expect(await bip39.mnemonicToSeedHex(vmnemonic, normalizedPassword)).toEqual(vseedHex); // 'mnemonicToSeedHex leaves normalizes passwords as-is',
});

test('README example 1', () => {
  const entropy = 'ffffffffffffffffffffffffffffffff';
  const mnemonic = bip39.entropyToMnemonic(entropy);

  expect(mnemonic).toEqual('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');

  // reversible
  expect(bip39.mnemonicToEntropy(mnemonic)).toEqual(entropy);
});

test('README example 2', async () => {
  mockGenerateSecureRandomAsBase64.mockImplementationOnce(async (length) => {
    return Buffer.from('qwertyuiopasdfghjklzxcvbnm[];,./'.slice(0, length)).toString('base64');
  });

  const mnemonic = await bip39.generateMnemonic();

  expect(mnemonic).toEqual(
    'imitate robot frame trophy nuclear regret saddle around inflict case oil spice',
  );
  expect(bip39.validateMnemonic(mnemonic)).toBe(true);
});

test('README example 3', async () => {
  const mnemonic = 'basket actual';
  const seed = await bip39.mnemonicToSeed(mnemonic);
  const seedHex = await bip39.mnemonicToSeedHex(mnemonic);

  expect(seed.toString('hex')).toEqual(seedHex);
  // TODO FIXME
  expect(seedHex).toEqual(
    '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f',
  );
  expect(bip39.validateMnemonic(mnemonic)).toBe(false);
});

test('invalid entropy', () => {
  expect(() => {
    bip39.entropyToMnemonic(Buffer.from('', 'hex'));
  }).toThrow(/^Invalid entropy$/); // 'throws for empty entropy')

  expect(() => {
    bip39.entropyToMnemonic(Buffer.from('000000', 'hex'));
  }).toThrow(/^Invalid entropy$/); // "throws for entropy that's not a multitude of 4 bytes",

  expect(() => {
    bip39.entropyToMnemonic(Buffer.from(new Array(1028 + 1).join('00'), 'hex'));
  }).toThrow(/^Invalid entropy$/); // 'throws for entropy that is larger than 1024',
});

test('generateMnemonic can vary entropy length', async () => {
  const words = (await bip39.generateMnemonic(160)).split(' ');

  expect(words.length).toBe(15); // 'can vary generated entropy bit length');
});

test('generateMnemonic only requests the exact amount of data from an RNG', async () => {
  expect.assertions(1);

  await bip39.generateMnemonic(160, async (size) => {
    expect(size).toEqual(160 / 8);
    return Buffer.alloc(size);
  });
});

test('generateMnemonic rejects invalid entropy', async () => {
  expect(bip39.generateMnemonic(6)).rejects.toThrowError(/^Invalid entropy$/);
});

test('validateMnemonic', () => {
  expect(bip39.validateMnemonic('sleep kitten')).toBe(false); // 'fails for a mnemonic that is too short');
  expect(bip39.validateMnemonic('sleep kitten sleep kitten sleep kitten')).toBe(false); // 'fails for a mnemonic that is too short',
  expect(
    bip39.validateMnemonic(
      'turtle front uncle idea crush write shrug there lottery flower risky shell',
    ),
  ).toBe(false); // 'fails if mnemonic words are not in the word list',
  expect(
    bip39.validateMnemonic(
      'sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten',
    ),
  ).toBe(false); // 'fails for invalid checksum',
});

test('exposes standard wordlists', () => {
  expect(bip39.wordlists.EN.length).toEqual(2048);
  expect(typeof bip39.wordlists.EN[0]).toBe('string');
  expect(bip39.wordlists.EN).toEqual(DEFAULT_WORDLIST);
});
