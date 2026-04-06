const mongoose = require('mongoose');
const sc = require('@tsmx/string-crypto');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption EncryptedDate test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';
    const testDate = new Date('2024-06-15T10:30:00.000Z');
    const testDate2 = new Date('1985-03-22T08:00:00.000Z');

    var mongoServer = null;
    var Contract = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-date' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            startDate: { type: Date, encrypted: true },
            birthDate: { type: Date, encrypted: true }
        });
        schema.plugin(plugin);
        Contract = mongoose.model('Contract', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testContract = new Contract();
        testContract.id = 'id-test';
        testContract.startDate = testDate;
        testContract.birthDate = testDate2;
        await testContract.save();
    });

    afterEach(async () => {
        await Contract.deleteMany();
    });

    it('tests a successful document creation', async () => {
        const contract = new Contract();
        contract.id = 'id-1';
        contract.startDate = testDate;
        contract.birthDate = testDate2;
        const saved = await contract.save();
        expect(saved).toBeDefined();
        expect(saved._id).toBeDefined();
        expect(saved.startDate.toISOString()).toStrictEqual(testDate.toISOString());
        expect(saved.birthDate.toISOString()).toStrictEqual(testDate2.toISOString());
        const lean = await Contract.findById(saved._id).lean();
        expect(typeof lean.startDate).toStrictEqual('string');
        expect(lean.startDate.split('|').length).toStrictEqual(3);
        expect(typeof lean.birthDate).toStrictEqual('string');
        expect(lean.birthDate.split('|').length).toStrictEqual(3);
    });

    it('tests a successful document update', async () => {
        const contract = await Contract.findOne({ id: 'id-test' });
        expect(contract).toBeDefined();
        expect(contract.startDate.toISOString()).toStrictEqual(testDate.toISOString());
        const newDate = new Date('2025-01-01T00:00:00.000Z');
        contract.startDate = newDate;
        await contract.save();
        const updated = await Contract.findOne({ id: 'id-test' });
        expect(updated.startDate.toISOString()).toStrictEqual(newDate.toISOString());
        expect(updated.birthDate.toISOString()).toStrictEqual(testDate2.toISOString());
    });

    it('tests a successful document creation and retrieval with null values', async () => {
        const contract = new Contract();
        contract.id = 'id-null';
        contract.startDate = null;
        contract.birthDate = testDate2;
        const saved = await contract.save();
        expect(saved.startDate).toStrictEqual(null);
        expect(saved.birthDate.toISOString()).toStrictEqual(testDate2.toISOString());
        const retrieved = await Contract.findOne({ id: 'id-null' });
        expect(retrieved.startDate).toStrictEqual(null);
        expect(retrieved.birthDate.toISOString()).toStrictEqual(testDate2.toISOString());
    });

    it('tests a successful manual decryption of a document from a lean query', async () => {
        const lean = await Contract.findOne({ id: 'id-test' }).lean();
        expect(typeof lean.startDate).toStrictEqual('string');
        expect(typeof lean.birthDate).toStrictEqual('string');
        expect(new Date(sc.decrypt(lean.startDate, { key: testKey })).toISOString())
            .toStrictEqual(testDate.toISOString());
        expect(new Date(sc.decrypt(lean.birthDate, { key: testKey })).toISOString())
            .toStrictEqual(testDate2.toISOString());
    });

});
