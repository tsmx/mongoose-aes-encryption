const mongoose = require('mongoose');
const sc = require('@tsmx/string-crypto');
const { MongoMemoryServer } = require('mongodb-memory-server');
const configure = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption EncryptedString test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Person = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-string' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = configure({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            firstName: { type: String, encrypted: true },
            lastName: { type: String, encrypted: true }
        });
        schema.plugin(plugin);
        Person = mongoose.model('Person', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testPerson = new Person();
        testPerson.id = 'id-test';
        testPerson.firstName = 'FirstNameTest';
        testPerson.lastName = 'LastNameTest';
        await testPerson.save();
    });

    afterEach(async () => {
        await Person.deleteMany();
    });

    it('tests a successful document creation', async () => {
        const person = new Person();
        person.id = 'id-1';
        person.firstName = 'Hans';
        person.lastName = 'Müller';
        const saved = await person.save();
        expect(saved).toBeDefined();
        expect(saved._id).toBeDefined();
        expect(saved.firstName).toStrictEqual('Hans');
        expect(saved.lastName).toStrictEqual('Müller');
        const lean = await Person.findById(saved._id).lean();
        expect(lean.firstName).not.toStrictEqual('Hans');
        expect(lean.firstName.split('|').length).toStrictEqual(3);
        expect(lean.lastName).not.toStrictEqual('Müller');
        expect(lean.lastName.split('|').length).toStrictEqual(3);
    });

    it('tests a successful document update', async () => {
        const person = await Person.findOne({ id: 'id-test' });
        expect(person).toBeDefined();
        expect(person.firstName).toStrictEqual('FirstNameTest');
        expect(person.lastName).toStrictEqual('LastNameTest');
        person.firstName = 'UpdatedFirstName';
        await person.save();
        const updated = await Person.findOne({ id: 'id-test' });
        expect(updated.firstName).toStrictEqual('UpdatedFirstName');
        expect(updated.lastName).toStrictEqual('LastNameTest');
    });

    it('tests a successful document creation and retrieval with null values', async () => {
        const person = new Person();
        person.id = 'id-null';
        person.firstName = null;
        person.lastName = 'Müller';
        const saved = await person.save();
        expect(saved.firstName).toStrictEqual(null);
        expect(saved.lastName).toStrictEqual('Müller');
        const retrieved = await Person.findOne({ id: 'id-null' });
        expect(retrieved.firstName).toStrictEqual(null);
        expect(retrieved.lastName).toStrictEqual('Müller');
    });

    it('tests a successful manual decryption of a document from a lean query', async () => {
        const lean = await Person.findOne({ id: 'id-test' }).lean();
        expect(lean.firstName).not.toStrictEqual('FirstNameTest');
        expect(lean.firstName.split('|').length).toStrictEqual(3);
        expect(lean.lastName).not.toStrictEqual('LastNameTest');
        expect(lean.lastName.split('|').length).toStrictEqual(3);
        expect(sc.decrypt(lean.firstName, { key: testKey })).toStrictEqual('FirstNameTest');
        expect(sc.decrypt(lean.lastName, { key: testKey })).toStrictEqual('LastNameTest');
    });

    it('tests failed decryption due to tampered authTag', async () => {
        const lean = await Person.findOne({ id: 'id-test' }).lean();
        const parts = lean.firstName.split('|');
        parts[1] = parts[1][0] === 'a' ? 'b' + parts[1].slice(1) : 'a' + parts[1].slice(1);
        const tampered = parts.join('|');
        await mongoose.connection.collection('people').updateOne(
            { id: 'id-test' },
            { $set: { firstName: tampered } }
        );
        const person = await Person.findOne({ id: 'id-test' });
        expect(() => person.firstName).toThrow();
    });

});
