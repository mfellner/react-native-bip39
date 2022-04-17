import * as bip39 from '@mfellner/react-native-bip39';
import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { useTests } from './use-tests';

export default function App() {
  const [state, setState] = useState<string | Error | undefined>();
  const testResults = useTests();

  useEffect(() => {
    const run = async () => {
      const mnemonic = await bip39.generateMnemonic();
      console.log('mnemonic:', mnemonic);
      setState(mnemonic);
    };
    run().catch(setState);
  }, []);

  return (
    <View style={styles.container}>
      {state instanceof Error ? (
        <Text>
          {state.name} {state.message}
        </Text>
      ) : (
        <>
          <Text>Mnemonic:</Text>
          <Text>{state}</Text>
        </>
      )}

      {testResults}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
});
