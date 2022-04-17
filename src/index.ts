import { createHash } from '@mfellner/react-native-fast-create-hash';
import { Buffer } from 'buffer';
import { pbkdf2 } from 'react-native-fast-crypto';
import { generateSecureRandom } from 'react-native-securerandom';
import unorm from 'unorm';
import DEFAULT_WORDLIST from '../wordlists/en.json';
import SPANISH_WORDLIST from '../wordlists/es.json';
import JAPANESE_WORDLIST from '../wordlists/ja.json';

declare global {
  interface Uint8Array {
    toString(encoding?: string): string;
  }
}

type RandomNumberGenerator = (size: number) => Promise<Uint8Array>;

const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';

export async function mnemonicToSeed(mnemonic: string, password?: string) {
  const mnemonicBuffer = Buffer.from(normalize(mnemonic), 'utf8');
  const saltBuffer = Buffer.from(salt(normalize(password)), 'utf8');
  return pbkdf2.deriveAsync(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512');
}

export async function mnemonicToSeedHex(mnemonic: string, password = '') {
  const seed = await mnemonicToSeed(mnemonic, password);
  return seed.toString('hex');
}

export async function mnemonicToEntropy(mnemonic: string, wordlist: string[] = DEFAULT_WORDLIST) {
  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }
  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word) => {
      const index = wordlist.indexOf(word);
      if (index === -1) {
        throw new Error(INVALID_MNEMONIC);
      }
      return lpad(index.toString(2), '0', 11);
    })
    .join('');
  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);
  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g)?.map(binaryToByte) || [];
  if (entropyBytes.length < 16) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 !== 0) {
    throw new Error(INVALID_ENTROPY);
  }
  const entropy = Buffer.from(entropyBytes);
  const newChecksum = await deriveChecksumBits(entropy);
  if (newChecksum !== checksumBits) {
    throw new Error(INVALID_CHECKSUM);
  }
  return entropy.toString('hex');
}

export async function entropyToMnemonic(entropy: string | Buffer, wordlist: string[] = DEFAULT_WORDLIST) {
  if (typeof entropy === 'string') {
    entropy = Buffer.from(entropy, 'hex');
  }
  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksumBits = await deriveChecksumBits(entropy);
  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g);
  if (!chunks) {
    throw new TypeError(INVALID_ENTROPY);
  }
  const words = chunks.map((binary) => {
    const index = binaryToByte(binary);
    return wordlist[index];
  });
  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
}

export async function generateMnemonic(
  strength = 128,
  rng: RandomNumberGenerator = generateSecureRandom,
  wordlist: string[] = DEFAULT_WORDLIST,
) {
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const bytes = await rng(strength / 8);
  const hexBuffer = Buffer.from(bytes);

  return entropyToMnemonic(hexBuffer, wordlist);
}

export async function validateMnemonic(mnemonic: string, wordlist?: string[]) {
  try {
    await mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}

function salt(password: string) {
  return 'mnemonic' + (unorm.nfkd(password) || ''); // Use unorm until String.prototype.normalize gets better browser support
}

//=========== helper methods from bitcoinjs-lib ========

function bytesToBinary(bytes: number[]): string {
  return bytes.map((x: number): string => lpad(x.toString(2), '0', 8)).join('');
}

function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}

function normalize(str = ''): string {
  return str.normalize('NFKD');
}

function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

async function deriveChecksumBits(entropyBuffer: Buffer) {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = await createHash(entropyBuffer, 'sha256');
  return bytesToBinary(Array.from(hash)).slice(0, CS);
}

export const wordlists = {
  EN: DEFAULT_WORDLIST,
  ES: SPANISH_WORDLIST,
  JA: JAPANESE_WORDLIST,
};
