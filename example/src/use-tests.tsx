import * as bip39 from '@mfellner/react-native-bip39';
import React, { useEffect, useState } from 'react';
import { Text } from 'react-native';
import { expect, test } from './utils';

export function useTests() {
  const [testResults, setTestResults] = useState<string[] | Error>([]);

  useEffect(() => {
    const run = async () => {
      const results = await Promise.all([
        test('README example 1', async () => {
          const entropy = 'ffffffffffffffffffffffffffffffff';
          const mnemonic = await bip39.entropyToMnemonic(entropy);

          expect(mnemonic).toEqual('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');

          // reversible
          expect(await bip39.mnemonicToEntropy(mnemonic)).toEqual(entropy);
        }),
        test('README example 3', async () => {
          const mnemonic = 'basket actual';
          const seed = await bip39.mnemonicToSeed(mnemonic);
          const seedHex = await bip39.mnemonicToSeedHex(mnemonic);

          expect(seed.toString('hex')).toEqual(seedHex);

          expect(seedHex).toEqual(
            '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f',
          );
          expect(await bip39.validateMnemonic(mnemonic)).toBe(false);
        }),
        test('generateMnemonic can vary entropy length', async () => {
          const words = (await bip39.generateMnemonic(160)).split(' ');

          expect(words.length).toBe(15);
        }),
      ]);

      setTestResults(results);
    };
    run().catch(setTestResults);
  }, []);

  if (testResults instanceof Error) {
    return (
      <Text>
        Failed to run tests: {testResults.name} {testResults.message}
      </Text>
    );
  }
  return (
    <>
      <Text>Tests:</Text>
      {testResults.map((result) => (
        <Text key={result}>{result}</Text>
      ))}
    </>
  );
}
