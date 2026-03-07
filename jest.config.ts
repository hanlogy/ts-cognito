import type { Config } from 'jest';
import { createDefaultPreset, pathsToModuleNameMapper } from 'ts-jest';

const config: Config = {
  ...createDefaultPreset({
    tsconfig: '<rootDir>/tsconfig.jest.json',
  }),
  testEnvironment: 'node',
  moduleNameMapper: pathsToModuleNameMapper(
    {
      '@/test/*': ['test/*'],
      '@/*': ['src/*'],
    },
    {
      prefix: '<rootDir>',
    },
  ),
  moduleFileExtensions: ['js', 'ts'],
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
};

export default config;
