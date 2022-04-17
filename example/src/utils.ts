export async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    return `Passed: ${name}`;
  } catch (err) {
    return `Failed: ${name} (${err instanceof Error ? err.message : ''})`;
  }
}

export function expect(actual: any) {
  return {
    toEqual(expected: any) {
      if (actual !== expected) {
        throw new Error(`Expected ${expected} but received ${actual}`);
      }
    },
    toBe(expected: any) {
      if (actual !== expected) {
        throw new Error(`Expected ${expected} but received ${actual}`);
      }
    },
  };
}
