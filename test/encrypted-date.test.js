const mongoose = require('mongoose');
const { decrypt } = require('../mongoose-aes-encryption');
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
        expect(new Date(decrypt(lean.startDate, { key: testKey })).toISOString())
            .toStrictEqual(testDate.toISOString());
        expect(new Date(decrypt(lean.birthDate, { key: testKey })).toISOString())
            .toStrictEqual(testDate2.toISOString());
    });

});

describe('mongoose-aes-encryption EncryptedDate array test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';
    const dateA = new Date('2024-01-15T12:00:00.000Z');
    const dateB = new Date('2025-06-01T09:30:00.000Z');
    const dateC = new Date('2023-11-20T00:00:00.000Z');

    var mongoServer = null;
    var Project = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-date-array' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            milestones: { type: [Date], encrypted: true },
            deadlines: { type: [Date], encrypted: true }
        });
        schema.plugin(plugin);
        Project = mongoose.model('Project', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testProject = new Project();
        testProject.id = 'id-test';
        testProject.milestones = [dateA, dateB];
        testProject.deadlines = [dateC];
        await testProject.save();
    });

    afterEach(async () => {
        await Project.deleteMany();
    });

    it('tests a successful document creation', async () => {
        const project = new Project();
        project.id = 'id-1';
        project.milestones = [dateA, dateB];
        project.deadlines = [dateC];
        const saved = await project.save();
        expect(saved).toBeDefined();
        expect(saved._id).toBeDefined();
        expect(saved.milestones.map(d => d.toISOString())).toStrictEqual([dateA.toISOString(), dateB.toISOString()]);
        expect(saved.deadlines.map(d => d.toISOString())).toStrictEqual([dateC.toISOString()]);
        const lean = await Project.findById(saved._id).lean();
        expect(Array.isArray(lean.milestones)).toStrictEqual(true);
        lean.milestones.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
        expect(Array.isArray(lean.deadlines)).toStrictEqual(true);
        lean.deadlines.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
    });

    it('tests a successful document update', async () => {
        const project = await Project.findOne({ id: 'id-test' });
        expect(project).toBeDefined();
        expect(project.milestones.map(d => d.toISOString())).toStrictEqual([dateA.toISOString(), dateB.toISOString()]);
        const newDate = new Date('2026-03-01T00:00:00.000Z');
        project.milestones = [newDate];
        await project.save();
        const updated = await Project.findOne({ id: 'id-test' });
        expect(updated.milestones.map(d => d.toISOString())).toStrictEqual([newDate.toISOString()]);
        expect(updated.deadlines.map(d => d.toISOString())).toStrictEqual([dateC.toISOString()]);
    });

    it('tests a successful document creation and retrieval with a null field', async () => {
        const project = new Project();
        project.id = 'id-null';
        project.milestones = null;
        project.deadlines = [dateC];
        const saved = await project.save();
        expect(saved.milestones).toStrictEqual(null);
        expect(saved.deadlines.map(d => d.toISOString())).toStrictEqual([dateC.toISOString()]);
        const retrieved = await Project.findOne({ id: 'id-null' });
        expect(retrieved.milestones).toStrictEqual(null);
        expect(retrieved.deadlines.map(d => d.toISOString())).toStrictEqual([dateC.toISOString()]);
    });

    it('tests a successful document creation and retrieval with an empty array', async () => {
        const project = new Project();
        project.id = 'id-empty';
        project.milestones = [];
        project.deadlines = [dateA];
        const saved = await project.save();
        expect(saved.milestones).toStrictEqual([]);
        const retrieved = await Project.findOne({ id: 'id-empty' });
        expect(retrieved.milestones).toStrictEqual([]);
        expect(retrieved.deadlines.map(d => d.toISOString())).toStrictEqual([dateA.toISOString()]);
    });

    it('tests a successful manual decryption of a document from a lean query', async () => {
        const lean = await Project.findOne({ id: 'id-test' }).lean();
        expect(Array.isArray(lean.milestones)).toStrictEqual(true);
        lean.milestones.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
        expect(lean.milestones.map(elem => new Date(decrypt(elem, { key: testKey })).toISOString()))
            .toStrictEqual([dateA.toISOString(), dateB.toISOString()]);
        expect(lean.deadlines.map(elem => new Date(decrypt(elem, { key: testKey })).toISOString()))
            .toStrictEqual([dateC.toISOString()]);
    });

    it('tests a successful document creation and retrieval with an array containing null elements', async () => {
        const project = new Project();
        project.id = 'id-null-elem';
        project.milestones = [dateA, null, dateB];
        project.deadlines = [dateC];
        const saved = await project.save();
        expect(saved.milestones[0].toISOString()).toStrictEqual(dateA.toISOString());
        expect(saved.milestones[1]).toBeNull();
        expect(saved.milestones[2].toISOString()).toStrictEqual(dateB.toISOString());
        const retrieved = await Project.findOne({ id: 'id-null-elem' });
        expect(retrieved.milestones[0].toISOString()).toStrictEqual(dateA.toISOString());
        expect(retrieved.milestones[1]).toBeNull();
        expect(retrieved.milestones[2].toISOString()).toStrictEqual(dateB.toISOString());
        const lean = await Project.findOne({ id: 'id-null-elem' }).lean();
        expect(lean.milestones[0].split('|').length).toStrictEqual(3);
        expect(lean.milestones[1]).toBeNull();
        expect(lean.milestones[2].split('|').length).toStrictEqual(3);
    });

});
