const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');

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

    it('tests that find() by a searchable field is transparent', async () => {
        const results = await User.find({ email: 'alice@example.com' });
        expect(results.length).toStrictEqual(1);
        expect(results[0].username).toStrictEqual('alice');
        expect(results[0].email).toStrictEqual('alice@example.com');
    });

    it('tests that findOne() by a searchable field is transparent', async () => {
        const user = await User.findOne({ email: 'alice@example.com' });
        expect(user).not.toBeNull();
        expect(user.username).toStrictEqual('alice');
        expect(user.email).toStrictEqual('alice@example.com');
    });

    it('tests that findOne() by a searchable Number field is transparent', async () => {
        const user = await User.findOne({ salary: 75000 });
        expect(user).not.toBeNull();
        expect(user.username).toStrictEqual('alice');
        expect(user.salary).toStrictEqual(75000);
    });

    it('tests that findOne() returns null when the value does not match', async () => {
        const user = await User.findOne({ email: 'other@example.com' });
        expect(user).toBeNull();
    });

    it('tests that countDocuments() by a searchable field is transparent', async () => {
        const user2 = new User({ username: 'bob', email: 'alice@example.com', salary: 50000 });
        await user2.save();
        const count = await User.countDocuments({ email: 'alice@example.com' });
        expect(count).toStrictEqual(2);
    });

    it('tests that findOneAndUpdate() by a searchable field is transparent', async () => {
        const updated = await User.findOneAndUpdate(
            { email: 'alice@example.com' },
            { username: 'alice-updated' },
            { returnDocument: 'after' }
        );
        expect(updated).not.toBeNull();
        expect(updated.username).toStrictEqual('alice-updated');
        expect(updated.email).toStrictEqual('alice@example.com');
    });

    it('tests that deleteOne() by a searchable field is transparent', async () => {
        await User.deleteOne({ email: 'alice@example.com' });
        const count = await User.countDocuments({ username: 'alice' });
        expect(count).toStrictEqual(0);
    });

    it('tests that updateOne() by a searchable field is transparent', async () => {
        await User.updateOne({ email: 'alice@example.com' }, { username: 'alice-updated' });
        const user = await User.findOne({ email: 'alice@example.com' });
        expect(user.username).toStrictEqual('alice-updated');
    });

    it('tests that non-searchable fields in the same query are left untouched', async () => {
        const user = await User.findOne({ username: 'alice', email: 'alice@example.com' });
        expect(user).not.toBeNull();
        expect(user.username).toStrictEqual('alice');
    });

    it('tests that updating a document updates the __search_ shadow field', async () => {
        const leanBefore = await User.findOne({ username: 'alice' }).lean();
        const originalHash = leanBefore.__search_email;
        const user = await User.findOne({ username: 'alice' });
        user.email = 'newalice@example.com';
        await user.save();
        const leanAfter = await User.findOne({ username: 'alice' }).lean();
        expect(leanAfter.__search_email).not.toStrictEqual(originalHash);
        // New value is now findable transparently
        const found = await User.findOne({ email: 'newalice@example.com' });
        expect(found).not.toBeNull();
        expect(found.username).toStrictEqual('alice');
        // Old value is no longer findable
        const notFound = await User.findOne({ email: 'alice@example.com' });
        expect(notFound).toBeNull();
    });

    it('tests that null values result in a null __search_ shadow field', async () => {
        const user = new User({ username: 'bob', email: null, salary: 50000 });
        await user.save();
        const lean = await User.findOne({ username: 'bob' }).lean();
        expect(lean.__search_email).toBeNull();
    });

    it('tests that querying by null on a searchable field is transparent', async () => {
        const user = new User({ username: 'bob', email: null, salary: 50000 });
        await user.save();
        const found = await User.findOne({ email: null });
        expect(found).not.toBeNull();
        expect(found.username).toStrictEqual('bob');
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
