# AGENTS.md — Developer & Agent Guide

This file provides guidance for coding agents and human contributors working in
the `@tsmx/mongoose-aes-encryption` repository.

---

## Project Overview

A Mongoose plugin that adds transparent AES encryption at rest to schema fields.
Fields marked with `encrypted: true` are automatically encrypted on write and
decrypted on read. Encryption/decryption is delegated to `@tsmx/string-crypto`.
Supports scalar fields and single-element array fields for all four types, as well
as inline nested sub-documents and separate sub-schemas.

- **Language:** Plain JavaScript (CommonJS, no TypeScript, no build step)
- **Single source file:** `mongoose-aes-encryption.js`
- **Test directory:** `test/`

---

## Commands

### Run all tests
```bash
npm test
```

### Run all tests with coverage
```bash
npm run test-coverage
```

### Run a single test file
```bash
npx jest test/plugin.test.js
npx jest test/encrypted-string.test.js
npx jest test/encrypted-number.test.js
npx jest test/encrypted-date.test.js
npx jest test/encrypted-boolean.test.js
npx jest test/complex.test.js
```

### Run a single test by name
```bash
npx jest -t "tests a successful document creation"
```

### Lint (no script alias — invoke directly)
```bash
npx eslint .
```

### Fix lint errors automatically
```bash
npx eslint . --fix
```

---

## Code Style

### Module system
- **CommonJS only.** Use `require()` and `module.exports`. Do not use ES module
  `import`/`export` syntax anywhere in this project.

### Formatting (enforced by ESLint — flat config in `eslint.config.js`)
- **Indentation:** 4 spaces (no tabs). `switch` case bodies are indented 1 level
  inside the `switch` (`SwitchCase: 1`).
- **Quotes:** Single quotes for all strings.
- **Semicolons:** Required at the end of every statement.
- No Prettier — all formatting rules come from ESLint.

### Variables
- Use `const` for imports and values that are never reassigned.
- Use `let` for variables that may be reassigned.
- Avoid `var` in new source code. Test files historically use `var` for top-level
  mutable lifecycle variables (`mongoServer`, model variables), but `const`/`let`
  is preferred going forward.

### Naming conventions
- **Functions:** camelCase — e.g. `makeGetterSetter`, `createAESPlugin`
- **Variables and parameters:** camelCase — e.g. `originalType`, `testKey`
- **Constants:** camelCase (not `SCREAMING_SNAKE_CASE`) — e.g. `allowedAlgorithms`
- **Unused parameters:** Prefix with `_` to silence the `no-unused-vars` warning —
  e.g. `function handler(_req, res) {}`

### Exports
- The module exports a single factory function:
  `module.exports = function createAESPlugin(options)`.
- `createAESPlugin` returns a Mongoose plugin function `encryptedPlugin(schema)`.
- No named exports, no default export object, no class exports.

### Functions and closures
- Prefer factory functions and closures over classes when sharing state via
  captured parameters (e.g. `key`, `algorithm`, `originalType`).
- The helper `makeGetterSetter(originalType, key, algorithm, isArray)` returns a
  `{ get, set }` pair — keep this pattern for any new type-specific logic.
- Avoid adding class hierarchies. The existing closure-based design is intentional.

### Error handling
- Throw `Error` instances with descriptive messages using template literals:
  ```js
  throw new Error(`mongoose-aes-encryption: invalid algorithm '${algorithm}'. Allowed: ${allowedAlgorithms.join(', ')}`);
  ```
- Always prefix error messages with `'mongoose-aes-encryption: '`.
- Do not silently swallow errors. Let errors from `@tsmx/string-crypto` and
  Mongoose propagate naturally.

### Async code
- Use `async/await` consistently. Do not use raw `.then()` / `.catch()` chains.

### Nulls / undefined
- `null` and `undefined` values must pass through unencrypted on both get and set.
- Use `passNull: true` in all `sc.encrypt()` / `sc.decrypt()` calls.
- Guard array elements individually: `elem == null ? elem : sc.encrypt(...)`.

---

## Architecture

### Plugin entry point
`createAESPlugin(options)` is the factory. Call it once and pass the returned
plugin function to `schema.plugin()` or `mongoose.plugin()`:
```js
const createAESPlugin = require('@tsmx/mongoose-aes-encryption');
const encryptedPlugin = createAESPlugin({ key, algorithm }); // 'aes-256-gcm' default
mongoose.plugin(encryptedPlugin);    // global — applies to all schemas
// or per schema:
mySchema.plugin(encryptedPlugin);
```

- Supported algorithms: `'aes-256-gcm'` (default) and `'aes-256-cbc'`.
- `options.key` is required; throws immediately if missing or `options` is omitted.
- `options.algorithm` defaults to `'aes-256-gcm'` (nullish coalescing `??`).

### How encryption is applied to a schema
`encryptedPlugin(schema)` uses `schema.eachPath()` to locate every path whose
options include `encrypted: true`. For each such path it records the `originalType`
(and whether it is an array). After the walk, it rewrites each path to
`Schema.Types.Mixed` with a `get`/`set` pair produced by `makeGetterSetter()`:

```js
schema.path(pathname, {
    ...existingOptions,
    type: schema.constructor.Types.Mixed,
    get,   // decrypts ciphertext → native type
    set    // converts native type → string, then encrypts
});
```

### Marking fields for encryption
Add `encrypted: true` to the field definition in the schema:
```js
const schema = new Schema({
    name:      { type: String,  encrypted: true },
    score:     { type: Number,  encrypted: true },
    birthdate: { type: Date,    encrypted: true },
    active:    { type: Boolean, encrypted: true },
    tags:      { type: [String], encrypted: true },  // array support
});
```

### Type conversion (`makeGetterSetter`)
| `originalType` | `toString(v)` (before encrypt) | `fromString(v)` (after decrypt) |
|---|---|---|
| `String`  | `String(v)` | identity |
| `Number`  | `String(v)` | `parseFloat(v)` |
| `Date`    | `new Date(v).toISOString()` | `new Date(v)` |
| `Boolean` | `String(v)` | `v === 'true'` |

### Wire format (MongoDB storage)
All fields store the encrypted value as a plain string:
- AES-256-GCM: `iv|authTag|ciphertext` (3 pipe-separated parts)
- AES-256-CBC: `iv|ciphertext` (2 pipe-separated parts)
- `null` / `undefined` values pass through unencrypted.

### lean() queries
Getters do not run on `.lean()` results — the raw ciphertext string is returned.
Manual decryption requires `@tsmx/string-crypto` directly:
```js
const sc = require('@tsmx/string-crypto');
const plain = sc.decrypt(leanDoc.field, { key });
const num   = parseFloat(sc.decrypt(leanDoc.numField, { key }));
const date  = new Date(sc.decrypt(leanDoc.dateField, { key }));
const bool  = sc.decrypt(leanDoc.boolField, { key }) === 'true';
```

---

## Test Conventions

### Framework
- **Jest** `^29` with `testEnvironment: 'node'` (see `jest.config.js`).
- Each test suite spins up an in-memory MongoDB via `mongodb-memory-server`.

### Test files
- `test/plugin.test.js` — factory error handling, algorithm validation, wire format
- `test/encrypted-string.test.js` — scalar String + `[String]` array
- `test/encrypted-number.test.js` — scalar Number + `[Number]` array
- `test/encrypted-date.test.js` — scalar Date + `[Date]` array
- `test/encrypted-boolean.test.js` — scalar Boolean + `[Boolean]` array
- `test/complex.test.js` — multi-type schemas, inline nested sub-documents, separate sub-schemas

### Test description style
- `describe` blocks: `'mongoose-aes-encryption EncryptedNumber test suite'`
- `it` descriptions start with `'tests'`:
  ```js
  it('tests a successful document creation', async () => { ... });
  it('tests that plugin creation throws when key is missing', () => { ... });
  ```

### Suite structure
```js
describe('suite name', () => {
    const testKey = '...';         // immutable constants at top
    var mongoServer = null;        // mutable lifecycle vars (var is acceptable here)
    var Model = null;

    beforeAll(async () => { /* start mongo, create plugin, define schema + model */ });
    afterAll(async () => { /* stop mongo */ });
    beforeEach(async () => { /* seed one document */ });
    afterEach(async () => { await Model.deleteMany(); });

    it('tests ...', async () => {
        // arrange / act / expect
    });
});
```

### Standard tests per type suite
Each scalar suite covers:
1. Successful document creation (value round-trips; lean shows ciphertext string)
2. Successful document update
3. Null passthrough (null stored and retrieved as null)
4. Manual lean decryption via `@tsmx/string-crypto`

Each array suite covers:
1. Successful document creation (array round-trips; lean shows array of ciphertext)
2. Successful document update
3. Null field passthrough
4. Empty array round-trip
5. Manual lean decryption

The `encrypted-string` suite additionally tests GCM authTag tamper detection.

---

## CI

GitHub Actions workflow: `.github/workflows/git-build.yml`

- Triggers on every push.
- Matrix: Node 18, 20, 22 on `ubuntu-latest`.
- Steps: `npm ci` → `npm run test` → `npm run test-coverage` → Coveralls upload.

All tests must pass on Node 18, 20, and 22 before any change is considered complete.
