module.exports = {
  projects: [
    {
      displayName: 'test',
      preset: 'react-native',
      moduleFileExtensions: ['ts', 'js', 'json'],
      transformIgnorePatterns: [
        'node_modules/(?!(jest-)?react-native|react-clone-referenced-element|@react-native-community|rollbar-react-native|@fortawesome|@react-native|@react-navigation)',
      ],
    },
    {
      displayName: 'lint',
      runner: 'jest-runner-eslint',
      testMatch: ['<rootDir>/{src,test}/**/*.ts', '<rootDir>/*.ts'],
    },
  ],
};
