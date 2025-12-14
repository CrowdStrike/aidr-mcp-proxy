import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['./src/proxy.ts'],
  clean: true,
  dts: false,
  fixedExtension: true,
  format: ['esm'],
  hash: false,
});
