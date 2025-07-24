import eslint from "@eslint/js";
import eslintPluginTypeScript from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import pluginChaiFriendly from "eslint-plugin-chai-friendly";
import mochaPlugin from "eslint-plugin-mocha";
import { globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config([
  globalIgnores(["coverage/**", "lib/**"]),
  eslint.configs.recommended,
  tseslint.configs.recommended,
  tseslint.configs.strict,
  mochaPlugin.configs.flat.recommended,
  {
    files: ["**/*"],
    rules: {
      "linebreak-style": ["error", "unix"],
    },
  },
  {
    files: ["**/*.{js,ts}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.eslint.json",
        ecmaVersion: 2020,
        sourceType: "module",
      },
      globals: { ...globals.node },
    },
    plugins: {
      "@typescript-eslint": eslintPluginTypeScript,
    },
    rules: {
      "no-console": "warn",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-unused-vars": "error",
      "@typescript-eslint/no-invalid-void-type": "off",
      "@typescript-eslint/no-dynamic-delete": "off",
      "@typescript-eslint/no-unused-expressions": "off",
    },
  },
  {
    files: ["**/*.spec.{js,ts}"],
    languageOptions: {
      globals: { ...globals.mocha },
    },
    plugins: {
      mocha: mochaPlugin,
      "chai-friendly": pluginChaiFriendly,
    },
    rules: {},
  },
  eslintConfigPrettier, // goes last
]);
