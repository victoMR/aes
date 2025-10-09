const globals = require("globals");
const js = require("@eslint/js");

module.exports = [
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.commonjs,
      }
    }
  },
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        ...globals.node,
        Buffer: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        process: "readonly",
      }
    },
    rules: {
      "no-unused-vars": ["error", { "argsIgnorePattern": "^(next|req|res)$" }],
      "no-redeclare": ["error", { "builtinGlobals": false }]
    }
  },
  {
    files: ["lib/**/*.js", "config/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.node,
      }
    }
  },
  {
    files: ["test/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        ...globals.node,
        ...globals.jest,
        test: "readonly",
        expect: "readonly",
        describe: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
        beforeAll: "readonly",
        afterAll: "readonly"
      }
    }
  }
];
