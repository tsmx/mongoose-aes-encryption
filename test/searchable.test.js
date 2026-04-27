const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');
const { encryptForSearch } = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption searchable fields test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var User = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-searchable' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey });
        const schema = new mongoose.Schema({
            username: { type: String },
            email: { type: String, encrypted: true, searchable: true },
            salary: { type: Number, encrypted: true, searchable: true },
            notes: { type: String, encrypted: true }
        });
        schema.plugin(plugin);
        User = mongoose.model('User', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const user = new User();
        user.username = 'alice';
        user.email = 'alice@example.com';
        user.salary = 75000;
        user.notes = 'some private note';
        await user.save();
    });

    afterEach(async () => {
        await User.deleteMany();
    });

    it('tests that searchable: true stores a __search_ shadow field on save', async () => {
        const lean = await User.findOne({ username: 'alice' }).lean();
        expect(lean.__search_email).toBeDefined();
        expect(typeof lean.__search_email).toStrictEqual('string');
        expect(lean.__search_email.length).toStrictEqual(64);
        expect(lean.__search_salary).toBeDefined();
        expect(typeof lean.__search_salary).toStrictEqual('string');
        expect(lean.__search_salary.length).toStrictEqual(64);
    });

    it('tests that a non-searchable encrypted field does not get a __search_ shadow field', async () => {
        const lean = await User.findOne({ username: 'alice' }).lean();
        expect(lean.__search_notes).toBeUndefined();
    });

    it('tests that the encrypted field still uses a random IV (non-deterministic ciphertext)', async () => {
        const user = new User({ username: 'bob', email: 'alice@example.com', salary: 75000 });
        await user.save();
        const leanAlice = await User.findOne({ username: 'alice' }).lean();
        const leanBob = await User.findOne({ username: 'bob' }).lean();
        expect(leanAlice.email).not.toStrictEqual(leanBob.email);
    });

    it('tests that two documents with the same value share the same __search_ hash', async () => {
        const user = new User({ username: 'bob', email: 'alice@example.com', salary: 75000 });
        await user.save();
        const leanAlice = await User.findOne({ username: 'alice' }).lean();
        const leanBob = await User.findOne({ username: 'bob' }).lean();
        expect(leanAlice.__search_email).toStrictEqual(leanBob.__search_email);
        expect(leanAlice.__search_salary).toStrictEqual(leanBob.__search_salary);
    });

    it('tests that find() by __search_ field returns the correct document', async () => {
        const hash = encryptForSearch('alice@example.com', { key: testKey });
        const results = await User.find({ __search_email: hash });
        expect(results.length).toStrictEqual(1);
        expect(results[0].username).toStrictEqual('alice');
        expect(results[0].email).toStrictEqual('alice@example.com');
    });

    it('tests that find() by __search_ field for a number returns the correct document', async () => {
        const hash = encryptForSearch(75000, { key: testKey });
        const results = await User.find({ __search_salary: hash });
        expect(results.length).toStrictEqual(1);
        expect(results[0].username).toStrictEqual('alice');
        expect(results[0].salary).toStrictEqual(75000);
    });

    it('tests that find() with a wrong value returns no results', async () => {
        const hash = encryptForSearch('other@example.com', { key: testKey });
        const results = await User.find({ __search_email: hash });
        expect(results.length).toStrictEqual(0);
    });

    it('tests that updating a document updates the __search_ field', async () => {
        const user = await User.findOne({ username: 'alice' });
        const originalHash = (await User.findOne({ username: 'alice' }).lean()).__search_email;
        user.email = 'newalice@example.com';
        await user.save();
        const lean = await User.findOne({ username: 'alice' }).lean();
        expect(lean.__search_email).not.toStrictEqual(originalHash);
        expect(lean.__search_email).toStrictEqual(encryptForSearch('newalice@example.com', { key: testKey }));
    });

    it('tests that null values result in a null __search_ field', async () => {
        const user = new User({ username: 'bob', email: null, salary: 50000 });
        await user.save();
        const lean = await User.findOne({ username: 'bob' }).lean();
        expect(lean.__search_email).toBeNull();
        expect(lean.__search_salary).toBeDefined();
    });

    it('tests that encryptForSearch returns a 64-char hex string', () => {
        const hash = encryptForSearch('test@example.com', { key: testKey });
        expect(typeof hash).toStrictEqual('string');
        expect(hash.length).toStrictEqual(64);
        expect(/^[0-9a-f]{64}$/.test(hash)).toStrictEqual(true);
    });

    it('tests that encryptForSearch is deterministic for the same value and key', () => {
        const h1 = encryptForSearch('alice@example.com', { key: testKey });
        const h2 = encryptForSearch('alice@example.com', { key: testKey });
        expect(h1).toStrictEqual(h2);
    });

    it('tests that encryptForSearch throws when key is missing', () => {
        expect(() => encryptForSearch('value', {}))
            .toThrow('mongoose-aes-encryption: options.key is required');
    });

    it('tests that encryptForSearch handles Date values', () => {
        const d = new Date('2024-01-15T10:00:00.000Z');
        const h1 = encryptForSearch(d, { key: testKey });
        const h2 = encryptForSearch(new Date('2024-01-15T10:00:00.000Z'), { key: testKey });
        expect(h1).toStrictEqual(h2);
        expect(h1.length).toStrictEqual(64);
    });

    it('tests that encryptForSearch handles boolean values', () => {
        const h1 = encryptForSearch(true, { key: testKey });
        const h2 = encryptForSearch(true, { key: testKey });
        const h3 = encryptForSearch(false, { key: testKey });
        expect(h1).toStrictEqual(h2);
        expect(h1).not.toStrictEqual(h3);
    });

});

describe('mongoose-aes-encryption searchable array fields test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Contact = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-searchable-array' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey });
        const schema = new mongoose.Schema({
            name: { type: String },
            tags: { type: [String], encrypted: true, searchable: true }
        });
        schema.plugin(plugin);
        Contact = mongoose.model('Contact', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const contact = new Contact();
        contact.name = 'alice';
        contact.tags = ['vip', 'customer'];
        await contact.save();
    });

    afterEach(async () => {
        await Contact.deleteMany();
    });

    it('tests that a searchable array field stores a pipe-joined __search_ shadow field', async () => {
        const lean = await Contact.findOne({ name: 'alice' }).lean();
        expect(typeof lean.__search_tags).toStrictEqual('string');
        const parts = lean.__search_tags.split('|');
        expect(parts.length).toStrictEqual(2);
        parts.forEach(p => expect(p.length).toStrictEqual(64));
    });

    it('tests that the array is still encrypted with random IVs', async () => {
        const contact2 = new Contact({ name: 'bob', tags: ['vip', 'customer'] });
        await contact2.save();
        const lean1 = await Contact.findOne({ name: 'alice' }).lean();
        const lean2 = await Contact.findOne({ name: 'bob' }).lean();
        expect(lean1.tags[0]).not.toStrictEqual(lean2.tags[0]);
    });

    it('tests that __search_ hashes match for the same array values across documents', async () => {
        const contact2 = new Contact({ name: 'bob', tags: ['vip', 'customer'] });
        await contact2.save();
        const lean1 = await Contact.findOne({ name: 'alice' }).lean();
        const lean2 = await Contact.findOne({ name: 'bob' }).lean();
        expect(lean1.__search_tags).toStrictEqual(lean2.__search_tags);
    });

    it('tests that an empty array results in an empty __search_ shadow field', async () => {
        const contact = new Contact({ name: 'bob', tags: [] });
        await contact.save();
        const lean = await Contact.findOne({ name: 'bob' }).lean();
        expect(lean.__search_tags).toStrictEqual('');
    });

    it('tests that a null array results in a null __search_ shadow field', async () => {
        const contact = new Contact({ name: 'bob', tags: null });
        await contact.save();
        const lean = await Contact.findOne({ name: 'bob' }).lean();
        expect(lean.__search_tags).toBeNull();
    });

});
