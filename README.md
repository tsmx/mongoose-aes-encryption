[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![npm version](https://img.shields.io/npm/v/mongoose-aes-encryption)
![node version](https://img.shields.io/node/v/mongoose-aes-encryption)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tsmx/mongoose-aes-encryption/git-build.yml?branch=master)](https://img.shields.io/github/actions/workflow/status/tsmx/mongoose-aes-encryption/git-build.yml?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/tsmx/mongoose-aes-encryption/badge.svg?branch=master)](https://coveralls.io/github/tsmx/mongoose-aes-encryption?branch=master)

# [**mongoose-aes-encryption**](https://github.com/tsmx/mongoose-aes-encryption)

> Easy to use Mongoose plugin providing AES-256-GCM encryption-at-rest with built-in tamper detection.

Adds AES encryption to individual Mongoose schema fields with minimal changes to existing schema definitions. All encryption and decryption is fully transparent: your application reads and writes plain values as usual while MongoDB stores only ciphertext.

For backwards compatibility, AES-256-CBC can also be used. See Options on how to set this explicitly.

## Key features

🔒 [Encrypted schema types](#plugin-setup)
- String, Number, Date, and Boolean fields supported as well as arrays of those
- [Inline nested sub-documents supported](#inline-nested-sub-documents)
- [Separate sub-schemas supported](#separate-sub-schemas)
- Transparent encryption on every save, transparent decryption on every read
- `null` values pass through unencrypted

🛡️ [Tamper detection via AES-256-GCM](#security)
- Authenticated encryption generates a cryptographic authentication tag alongside every ciphertext
- Any modification of the stored value — bit-flip, truncation, or substitution — invalidates the tag and causes decryption to throw
- Stored as `iv|authTag|ciphertext` in MongoDB

⚙️ [Minimal setup](#setup)
- Two lines of setup code before your schema definition
- One extra flag per encrypted field (`encrypted: true`) — no other schema changes required

See the [API reference](#api-reference) for full specs and examples.

---

## Usage

Suppose you have the following Mongoose schema with sensitive fields:

```javascript
const schema = new mongoose.Schema({
    username: { type: String },
    email:    { type: String },
    salary:   { type: Number },
    roles:    { type: [String] }
});
```

To encrypt `email`, `salary`, and `roles` at rest using AES-GCM, add two lines of setup and one flag per field:

```javascript
const createAESPlugin = require('mongoose-aes-encryption');
const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY });

const schema = new mongoose.Schema({
    username: { type: String },
    email:    { type: String,   encrypted: true },
    salary:   { type: Number,   encrypted: true },
    roles:    { type: [String], encrypted: true }
});
schema.plugin(plugin);
```

That's it — the rest of your code is unchanged:

```javascript
const User = mongoose.model('User', schema);

const user = new User({ username: 'alice', email: 'alice@example.com', salary: 75000, roles: ['admin', 'editor'] });
await user.save();
// MongoDB stores:
// { username: 'alice', email: '<iv|authTag|ciphertext>', salary: '<iv|authTag|ciphertext>',
//   roles: ['<iv|authTag|ciphertext>', '<iv|authTag|ciphertext>'] }

const found = await User.findOne({ username: 'alice' });
// Result: found.email  === 'alice@example.com'           (transparently decrypted)
// Result: found.salary === 75000                         (transparently decrypted)
// Result: found.roles  deep-equals ['admin', 'editor']   (each element transparently decrypted)
```

> `email`, `salary`, and `roles` are AES-256-GCM encrypted at rest — reads and writes work exactly as before.

### Inline nested sub-documents

Encrypted fields inside inline nested objects work without any extra steps. Apply the plugin once to the top-level schema — Mongoose traverses the nested object automatically.

```javascript
const createAESPlugin = require('mongoose-aes-encryption');
const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY });

// 'street' is encrypted; 'city' is stored as plain text
const schema = new mongoose.Schema({
    id:      { type: String, required: true },
    address: {
        street: { type: String, encrypted: true },
        city:   { type: String }
    }
});
schema.plugin(plugin); // one plugin call on the top-level schema is sufficient

const Location = mongoose.model('Location', schema);
```

Reads and writes use normal dot-notation — decryption is fully transparent:

```javascript
const loc = new Location({ id: 'loc-1', address: { street: '456 Oak Ave', city: 'Shelbyville' } });
await loc.save();
// MongoDB stores: { address: { street: '<iv|authTag|ciphertext>', city: 'Shelbyville' } }

const found = await Location.findOne({ id: 'loc-1' });
// Result: found.address.street === '456 Oak Ave'   (transparently decrypted)
// Result: found.address.city   === 'Shelbyville'   (plain — stored and returned as-is)

const lean = await Location.findOne({ id: 'loc-1' }).lean();
// Result: lean.address.street  === '<iv|authTag|ciphertext>'  (raw ciphertext — no getter)
// Result: lean.address.city    === 'Shelbyville'
```

### Separate sub-schemas

When a sub-schema is defined separately and embedded in a parent schema, apply the plugin to **both** the sub-schema and the parent schema. Calling it only on the parent schema will not encrypt fields defined in the sub-schema.

```javascript
const createAESPlugin = require('mongoose-aes-encryption');
const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY });

// Sub-schema: 'email' is encrypted, 'phone' is plain
const contactSchema = new mongoose.Schema({
    email: { type: String, encrypted: true },
    phone: { type: String }
});
contactSchema.plugin(plugin); // required — plugin must be applied to the sub-schema too

const employeeSchema = new mongoose.Schema({
    id:       { type: String, required: true },
    name:     { type: String, encrypted: true },
    contacts: [contactSchema]
});
employeeSchema.plugin(plugin);

const Employee = mongoose.model('Employee', employeeSchema);
```

Reads and writes work the same way — every encrypted field decrypts transparently regardless of nesting depth:

```javascript
const emp = new Employee({
    id: 'emp-1',
    name: 'Jane Doe',
    contacts: [
        { email: 'jane@example.com', phone: '555-1234' },
        { email: 'jane.doe@work.com', phone: '555-5678' }
    ]
});
await emp.save();
// MongoDB stores:
// { name: '<iv|authTag|ciphertext>',
//   contacts: [
//     { email: '<iv|authTag|ciphertext>', phone: '555-1234' },
//     { email: '<iv|authTag|ciphertext>', phone: '555-5678' }
//   ] }

const found = await Employee.findOne({ id: 'emp-1' });
// Result: found.name              === 'Jane Doe'           (transparently decrypted)
// Result: found.contacts[0].email === 'jane@example.com'   (transparently decrypted)
// Result: found.contacts[0].phone === '555-1234'           (plain — stored as-is)

const lean = await Employee.findOne({ id: 'emp-1' }).lean();
// Result: lean.name              === '<iv|authTag|ciphertext>'  (raw ciphertext)
// Result: lean.contacts[0].email === '<iv|authTag|ciphertext>'  (raw ciphertext)
// Result: lean.contacts[0].phone === '555-1234'                 (plain)
```

### Lean queries

Mongoose `.lean()` bypasses getters and returns the raw ciphertext stored in MongoDB. To decrypt manually, use [`@tsmx/string-crypto`](https://github.com/tsmx/string-crypto) directly:

```javascript
const sc = require('@tsmx/string-crypto');
const key = process.env.ENCRYPTION_KEY;

const doc = await User.findOne({ username: 'alice' }).lean();

const email    = sc.decrypt(doc.email, { key });                    // → string
const salary   = parseFloat(sc.decrypt(doc.salary, { key }));       // → number
const dob      = new Date(sc.decrypt(doc.birthDate, { key }));      // → Date
const active   = sc.decrypt(doc.active, { key }) === 'true';        // → boolean
```

---

## API Reference

### Plugin Setup

#### `createAESPlugin(options)`

Creates and returns a Mongoose plugin function that encrypts and decrypts schema fields. Call this once — before defining any schema that uses encrypted fields — and apply the returned plugin to each schema with `schema.plugin()`.

**Parameters:**
- `options` (Object): Configuration object.
  - `options.key` (string): 64-character hex string (32 bytes). **Required.**
  - `options.algorithm` (string, optional): Encryption algorithm. Default: `'aes-256-gcm'`.

**Returns:** `Function` — Mongoose plugin function, ready to pass to `schema.plugin()`.

**Example:**
```javascript
const mongoose = require('mongoose');
const createAESPlugin = require('mongoose-aes-encryption');

const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY });

const schema = new mongoose.Schema({
    name:      { type: String },
    email:     { type: String,  encrypted: true },
    birthDate: { type: Date,    encrypted: true },
    salary:    { type: Number,  encrypted: true },
    active:    { type: Boolean, encrypted: true }
});
schema.plugin(plugin);

const Employee = mongoose.model('Employee', schema);

const emp = new Employee({
    name: 'Bob', 
    email: 'bob@example.com',
    birthDate: new Date('1990-01-01'), 
    salary: 60000, 
    active: true
});
await emp.save();
// Result: name stored as plain text; all other fields stored as AES-256-GCM ciphertext

const found = await Employee.findById(emp._id);
// Result: found.email     === 'bob@example.com'
// Result: found.birthDate instanceof Date  → true
// Result: found.salary    === 60000
// Result: found.active    === true
```

---

## Installation

```bash
npm install mongoose-aes-encryption
```

---

## Options

To use the plugin with all defaults (AES-256-GCM), pass only the required key:

```javascript
const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY });
```

To customise the algorithm:

```javascript
const plugin = createAESPlugin({
    key:       process.env.ENCRYPTION_KEY,
    algorithm: 'aes-256-gcm'
});
```

### `key`

Type: `string`  
Required.

A 64-character hexadecimal string representing the 32-byte AES encryption key. All schemas that use the returned plugin share this key. Throws at configuration time if missing or if `options` is omitted entirely.

```javascript
const plugin = createAESPlugin({ key: 'a1b2c3d4e5f6...' }); // 64 hex chars
```

### `algorithm`

Type: `string`  
Default: `'aes-256-gcm'`

Encryption algorithm to use. `'aes-256-gcm'` (default) is an authenticated cipher that generates a tamper-detecting authentication tag for every value. `'aes-256-cbc'` is available for backwards compatibility with data encrypted before GCM support was introduced; it provides no tamper detection.

```javascript
// Backwards compatibility only
const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY, algorithm: 'aes-256-cbc' });
```

---

## Setup

1. Generate a 32-byte encryption key:

   ```bash
   openssl rand -hex 32
   ```

2. Store the key securely — an environment variable or a secrets manager. Never hardcode it.

   ```bash
   export ENCRYPTION_KEY=<your-64-char-hex-key>
   ```

3. Call `createAESPlugin()` once, before any schema that uses encrypted fields is defined:

   ```javascript
   const createAESPlugin = require('mongoose-aes-encryption');
   const plugin = createAESPlugin({ key: process.env.ENCRYPTION_KEY });
   ```

4. Apply the plugin to each schema and mark sensitive fields with `encrypted: true`:

   ```javascript
   const schema = new mongoose.Schema({
       name:  { type: String },
       email: { type: String, encrypted: true }
   });
   schema.plugin(plugin);
   ```

---

## Security

### AES-256-GCM — authenticated encryption with tamper detection

By default, `mongoose-aes-encryption` uses **AES-256-GCM**, an authenticated encryption mode. Every encrypted value is stored in MongoDB as a pipe-delimited string:

```
iv|authTag|ciphertext
```

The `authTag` is a cryptographic MAC computed over the ciphertext. On every read the authentication tag is verified before decryption. If the stored value has been modified in any way — bit-flip, truncation, or wholesale substitution — the tag check fails and decryption throws immediately. Corrupted or tampered ciphertext can never be silently read back as incorrect plaintext.

AES-256-CBC (available as `algorithm: 'aes-256-cbc'` for backwards compatibility) uses the wire format `iv|ciphertext` and provides no tamper detection.

### Lean queries expose raw ciphertext

`.lean()` results bypass Mongoose getters entirely. The raw `iv|authTag|ciphertext` string is returned as-is. If your application uses lean queries on collections that contain encrypted fields, treat those fields as opaque ciphertext and decrypt them explicitly with [`@tsmx/string-crypto`](https://github.com/tsmx/string-crypto).

### Null values

`null` fields are stored as `null` in MongoDB without encryption. Do not rely on `null` values being confidential.

---

## License

[MIT](https://github.com/tsmx/mongoose-aes-encryption/blob/master/LICENSE)
