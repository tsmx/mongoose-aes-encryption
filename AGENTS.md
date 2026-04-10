# AGENTS.md — Developer & Agent Guide

Guidance for coding agents and human contributors working in
`@tsmx/mongoose-aes-encryption`.

---

## Project Overview

A Mongoose plugin that adds transparent AES encryption at rest to schema fields.
Fields marked with `encrypted: true` are automatically encrypted on write and
decrypted on read. Supports scalar fields, single-element array fields
(`[String]`, `[Number]`, etc.), inline nested sub-documents, and separate
sub-schemas.

- **Language:** Plain JavaScript (CommonJS, no TypeScript, no build step)
- **Source files:** `mongoose-aes-encryption.js` (main plugin) + `lib/crypto.js` (inlined AES helpers)
- **Tests:** `test/` — 6 files, Jest + in-memory MongoDB

---

## Commands

```bash
# Run all tests
npm test

# Run all tests with coverage
npm run test-coverage

# Upload coverage to Coveralls (CI only)
npm run coveralls

# Run a single test file
npx jest test/plugin.test.js
npx jest test/encrypted-string.test.js
npx jest test/encrypted-number.test.js
npx jest test/encrypted-date.test.js
npx jest test/encrypted-boolean.test.js
npx jest test/complex.test.js

# Run a single test by name
npx jest -t "tests a successful document creation"

# Lint
npx eslint .

# Auto-fix lint errors
npx eslint . --fix
```

---

## Code Style

### Module system
CommonJS only — `require()` and `module.exports`. No ES module `import`/`export`.

### Formatting (ESLint flat config in `eslint.config.js`)
- **Indentation:** 4 spaces (no tabs); `SwitchCase: 1`
- **Quotes:** Single quotes for all strings
- **Semicolons:** Required on every statement
- No Prettier — formatting is enforced by ESLint alone

### Variables
- `const` for imports and never-reassigned values; `let` for reassigned variables
- Avoid `var` in new code. Existing test files use `var` for top-level mutable
  lifecycle variables (`mongoServer`, model) — this is acceptable but not preferred

### Naming
- **Functions/variables/constants:** camelCase — `makeGetterSetter`, `allowedAlgorithms`
- No `SCREAMING_SNAKE_CASE` for constants
- Prefix unused parameters with `_` to silence `no-unused-vars` — e.g. `_req`

### Exports
`module.exports = function createAESPlugin(options)` — a single factory function.
It returns `function encryptedPlugin(schema)`. Two named properties are also
attached as public API:
- `module.exports.encrypt` — encrypt a plaintext value with the given key
- `module.exports.decrypt` — decrypt a ciphertext value with the given key

These are stable semver-compatible exports. Use them for lean-query decryption and
manual operations (`$inc`/`$push` workarounds) instead of accessing `lib/crypto`
directly.

### Functions and closures
Prefer factory functions and closures over classes. `makeGetterSetter(originalType,
key, algorithm, isArray)` returns `{ get, set }` — follow this pattern for new
type-specific logic.

### Error handling
- Throw `Error` with a descriptive template-literal message.
- Always prefix: `'mongoose-aes-encryption: ...'`
- Let errors from Mongoose propagate; do not swallow them.

### Async code
`async/await` only. No raw `.then()` / `.catch()` chains.

### Nulls
`null` and `undefined` pass through unencrypted. Always use `passNull: true` in
`encrypt()` / `decrypt()`. Guard array elements individually:
`elem == null ? elem : encrypt(...)`.

---

## Architecture

### Plugin entry point
```js
const createAESPlugin = require('@tsmx/mongoose-aes-encryption');
const plugin = createAESPlugin({ key, algorithm }); // algorithm defaults to 'aes-256-gcm'
mongoose.plugin(plugin);     // global
mySchema.plugin(plugin);     // or per schema
```
Supported algorithms: `'aes-256-gcm'` (default) and `'aes-256-cbc'`.
`options.key` is required; throws immediately when missing.

### How fields are encrypted
`encryptedPlugin(schema)` calls `schema.eachPath()`, collects paths with
`encrypted: true`, then rewrites each to `Schema.Types.Mixed` with a `get`/`set`
pair from `makeGetterSetter()`. The `set` hook converts the native value to a
string and encrypts it; `get` decrypts and converts back.

### Type conversion table
| `originalType` | before encrypt (`toString`) | after decrypt (`fromString`) |
|---|---|---|
| `String`  | `String(v)` | identity |
| `Number`  | `String(v)` | `parseFloat(v)` |
| `Date`    | `new Date(v).toISOString()` | `new Date(v)` |
| `Boolean` | `String(v)` | `v === 'true'` |

### Wire format (stored in MongoDB)
- AES-256-GCM → `iv|authTag|ciphertext` (3 pipe-separated parts)
- AES-256-CBC → `iv|ciphertext` (2 pipe-separated parts)

### lean() queries
Getters do not run on `.lean()` results — raw ciphertext is returned. Decrypt
manually with `@tsmx/mongoose-aes-encryption`:
```js
const { decrypt } = require('@tsmx/mongoose-aes-encryption');
decrypt(doc.field, { key });                        // String
parseFloat(decrypt(doc.numField, { key }));         // Number
new Date(decrypt(doc.dateField, { key }));          // Date
decrypt(doc.boolField, { key }) === 'true';         // Boolean
```

---

## Test Conventions

### Files
- `test/plugin.test.js` — factory validation, algorithm checks, wire-format probes
- `test/encrypted-string.test.js` — scalar `String` + `[String]` array + GCM tamper test
- `test/encrypted-number.test.js` — scalar `Number` + `[Number]` array
- `test/encrypted-date.test.js` — scalar `Date` + `[Date]` array
- `test/encrypted-boolean.test.js` — scalar `Boolean` + `[Boolean]` array
- `test/complex.test.js` — mixed types, inline nested sub-documents, separate sub-schemas

### Suite structure
```js
describe('mongoose-aes-encryption <Name> test suite', () => {
    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';
    var mongoServer = null;   // var is conventional for mutable lifecycle vars
    var Model = null;

    beforeAll(async () => { /* start MongoMemoryServer, connect, define schema+model */ });
    afterAll(async () => { /* disconnect, stop server */ });
    beforeEach(async () => { /* seed one document */ });
    afterEach(async () => { await Model.deleteMany(); });

    it('tests ...', async () => { /* arrange / act / expect */ });
});
```
Note: `plugin.test.js` uses `beforeEach`/`afterEach` for the entire Mongoose
connection (creates and tears down a fresh connection per test) rather than once
per suite.

### Naming
- `describe`: `'mongoose-aes-encryption <Name> test suite'`
- `it`: descriptions always start with `'tests'`

### Standard coverage per type
Each scalar suite: creation round-trip, update, null passthrough, lean decryption.
Each array suite: adds empty-array and null-element-in-array cases.

---

## CI

- **`git-build.yml`** — triggers on every push; matrix Node 18/20/22;
  runs `npm ci` → `npm test` → `npm run test-coverage` → Coveralls upload.
- **`npm-publish.yml`** — manual `workflow_dispatch`; runs tests then `npm publish`.

All tests must pass on Node 18, 20, and 22 before any change is considered complete.
