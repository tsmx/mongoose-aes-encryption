const mongoose = require('mongoose');
const sc = require('@tsmx/string-crypto');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption EncryptedBoolean test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var User = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-boolean' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            active: { type: Boolean, encrypted: true },
            verified: { type: Boolean, encrypted: true }
        });
        schema.plugin(plugin);
        User = mongoose.model('User', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testUser = new User();
        testUser.id = 'id-test';
        testUser.active = true;
        testUser.verified = false;
        await testUser.save();
    });

    afterEach(async () => {
        await User.deleteMany();
    });

    it('tests a successful document creation with true and false values', async () => {
        const user = new User();
        user.id = 'id-1';
        user.active = true;
        user.verified = false;
        const saved = await user.save();
        expect(saved).toBeDefined();
        expect(saved._id).toBeDefined();
        expect(saved.active).toStrictEqual(true);
        expect(saved.verified).toStrictEqual(false);
        const lean = await User.findById(saved._id).lean();
        expect(typeof lean.active).toStrictEqual('string');
        expect(lean.active.split('|').length).toStrictEqual(3);
        expect(typeof lean.verified).toStrictEqual('string');
        expect(lean.verified.split('|').length).toStrictEqual(3);
    });

    it('tests that true and false both round-trip correctly', async () => {
        const userTrue = new User({ id: 'id-true', active: true, verified: true });
        const userFalse = new User({ id: 'id-false', active: false, verified: false });
        await userTrue.save();
        await userFalse.save();
        const retrievedTrue = await User.findOne({ id: 'id-true' });
        const retrievedFalse = await User.findOne({ id: 'id-false' });
        expect(retrievedTrue.active).toStrictEqual(true);
        expect(retrievedTrue.verified).toStrictEqual(true);
        expect(retrievedFalse.active).toStrictEqual(false);
        expect(retrievedFalse.verified).toStrictEqual(false);
    });

    it('tests a successful document update', async () => {
        const user = await User.findOne({ id: 'id-test' });
        expect(user).toBeDefined();
        expect(user.active).toStrictEqual(true);
        expect(user.verified).toStrictEqual(false);
        user.active = false;
        await user.save();
        const updated = await User.findOne({ id: 'id-test' });
        expect(updated.active).toStrictEqual(false);
        expect(updated.verified).toStrictEqual(false);
    });

    it('tests a successful document creation and retrieval with null values', async () => {
        const user = new User();
        user.id = 'id-null';
        user.active = null;
        user.verified = true;
        const saved = await user.save();
        expect(saved.active).toStrictEqual(null);
        expect(saved.verified).toStrictEqual(true);
        const retrieved = await User.findOne({ id: 'id-null' });
        expect(retrieved.active).toStrictEqual(null);
        expect(retrieved.verified).toStrictEqual(true);
    });

    it('tests a successful manual decryption of a document from a lean query', async () => {
        const lean = await User.findOne({ id: 'id-test' }).lean();
        expect(typeof lean.active).toStrictEqual('string');
        expect(typeof lean.verified).toStrictEqual('string');
        expect(sc.decrypt(lean.active, { key: testKey }) === 'true').toStrictEqual(true);
        expect(sc.decrypt(lean.verified, { key: testKey }) === 'true').toStrictEqual(false);
    });

});
