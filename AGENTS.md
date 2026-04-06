# AGENTS.md — Developer & Agent Guide

This file provides guidance for coding agents and human contributors working in
the `@tsmx/mongoose-aes-encryption` repository.

---

## Project Overview

A Mongoose plugin that registers four AES-encrypted SchemaTypes: `EncryptedString`,
`EncryptedNumber`, `EncryptedDate`, and `EncryptedBoolean`. Encryption/decryption
is delegated entirely to `@tsmx/string-crypto`. All four types store ciphertext
as a pipe-delimited string in MongoDB and transparently decrypt on read.

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

### Formatting (enforced by ESLint)
- **Indentation:** 4 spaces (no tabs). `switch` case bodies are indented 1 level
  inside the `switch`.
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
- **Classes:** PascalCase — e.g. `EncryptedBase`, `EncryptedString`
- **Functions and variables:** camelCase — e.g. `encryptedPlugin`, `testKey`
- **Constants:** camelCase (not `SCREAMING_SNAKE_CASE`) — e.g. `allowedAlgorithms`
- **Unused parameters:** Prefix with `_` to silence the `no-unused-vars` warning —
  e.g. `function handler(_req, res) {}`

### Exports
- The module exports a single function as `module.exports = function encryptedPlugin(...)`.
  No named exports, no default export object.
- None of the four SchemaType classes are exported directly; they are only
  accessible after plugin registration via `mongoose.Schema.Types.*`.

### Classes
- Use ES6 `class` syntax extending a base class.
- `EncryptedBase` holds the shared get/set logic and a static options object.
- Subclasses override `_toString(v)` and/or `_fromString(v)` for type-specific
  serialisation; they do not duplicate the encrypt/decrypt calls.
- Static class fields are used for shared mutable state:
  ```js
  static options = { key: null, algorithm: 'aes-256-gcm' };
  ```

### Error handling
- Throw `Error` instances with descriptive messages using template literals:
  ```js
  throw new Error(`mongoose-aes-encryption: invalid algorithm '${algorithm}'. Allowed: ${allowedAlgorithms.join(', ')}`);
  ```
- Do not silently swallow errors. Let errors from `@tsmx/string-crypto` and
  Mongoose propagate naturally.

### Async code
- Use `async/await` consistently. Do not use raw `.then()` / `.catch()` chains.

---

## Architecture

### Plugin entry point
`module.exports = function configure(options)` is the setup function. It must
be called once before any schema that uses the encrypted types is defined:
```js
const encryptedPlugin = require('@tsmx/mongoose-aes-encryption');
encryptedPlugin({ key, algorithm }); // registers types immediately on mongoose singleton
```
`configure()` returns a no-op Mongoose plugin function so the return value can
optionally be passed to `mongoose.plugin()` or `schema.plugin()`, but that call
is not required for type registration.

**Why not pure `mongoose.plugin()`:** Mongoose defers plugin execution until
`mongoose.model()` is called, which is after schema parsing. Custom SchemaTypes
must be registered before schemas are defined, so `configure()` attaches the
types synchronously via `require('mongoose')` (the singleton).

- Supported algorithms: `'aes-256-gcm'` (default) and `'aes-256-cbc'`.
- `options.key` is required; throws if missing or if `options` is omitted.

### Class hierarchy
```
SchemaType (Mongoose)
  └── EncryptedBase
        ├── EncryptedString   — cast: String(val)
        ├── EncryptedNumber   — _fromString: parseFloat(v); cast: String(val)
        ├── EncryptedDate     — _toString: toISOString(); _fromString: new Date(v); cast: String(val)
        └── EncryptedBoolean  — _fromString: v === 'true'; cast: String(val)
```

**Note on `cast()`:** Mongoose calls `cast()` on the setter's output (write path)
and on the raw DB value (read path). In both cases the value is already the
encrypted ciphertext string. All subclasses therefore implement `cast()` as
`String(val)`. Type conversion between native types and strings is handled
exclusively by `_toString()` (in the setter, before encryption) and `_fromString()`
(in the getter, after decryption).

### Wire format (MongoDB storage)
All four types store the encrypted value as a plain string:
- AES-256-GCM: `iv|authTag|ciphertext` (3 parts)
- AES-256-CBC: `iv|ciphertext` (2 parts)
- `null` values pass through unencrypted (`passNull: true`).

### lean() queries
Getters do not run on `.lean()` results — the raw encrypted string is returned.
Manual decryption requires `@tsmx/string-crypto` directly:
```js
const sc = require('@tsmx/string-crypto');
const plain = sc.decrypt(leanDoc.field, { key });           // → string
const num   = parseFloat(sc.decrypt(leanDoc.field, { key }));
const date  = new Date(sc.decrypt(leanDoc.field, { key }));
const bool  = sc.decrypt(leanDoc.field, { key }) === 'true';
```

---

## Test Conventions

### Framework
- **Jest** `^29` with `testEnvironment: 'node'`.
- Each test suite spins up an in-memory MongoDB via `mongodb-memory-server`.

### File naming
- `test/plugin.test.js` — registration and error-handling tests
- `test/encrypted-string.test.js`
- `test/encrypted-number.test.js`
- `test/encrypted-date.test.js`
- `test/encrypted-boolean.test.js`

### Test description style
- `describe` blocks: `'mongoose-aes-encryption EncryptedNumber test suite'`
- `it` descriptions start with `'tests'`:
  ```js
  it('tests a successful document creation', async () => { ... });
  it('tests that plugin registration throws when key is missing', () => { ... });
  ```

### Suite structure
```js
describe('suite name', () => {
    const testKey = '...';         // immutable constants at top
    var mongoServer = null;        // mutable lifecycle vars
    var Model = null;

    beforeAll(async () => { /* start mongo, call configure(), define model */ });
    afterAll(async () => { /* stop mongo */ });
    beforeEach(async () => { /* seed one document */ });
    afterEach(async () => { await Model.deleteMany(); });

    it('tests ...', async () => {
        // arrange / act / expect
    });
});
```

### Standard tests per type suite
Each type suite covers:
1. Successful document creation (value round-trips; lean shows encrypted string)
2. Successful document update (changed field updates, unchanged field preserved)
3. Null passthrough (null stored and retrieved as null)
4. Manual lean decryption (raw value decryptable with `@tsmx/string-crypto`)

The `encrypted-string` suite additionally tests GCM authTag tamper detection.

---

## CI

GitHub Actions workflows are in `.github/workflows/`:
- `git-build.yml` — runs `npm test` on Node 18, 20, and 22 for every push.

All tests must pass on Node 18, 20, and 22 before any change is considered
complete.
