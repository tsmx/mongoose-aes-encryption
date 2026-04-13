const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption plugin registration test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;

    beforeEach(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption' });
        await mongoose.connect(mongoServer.getUri());
    });

    afterEach(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    it('tests that createAESPlugin throws when key is missing', () => {
        expect(() => createAESPlugin({})).toThrow('mongoose-aes-encryption: options.key is required');
    });

    it('tests that createAESPlugin throws when options are missing entirely', () => {
        expect(() => createAESPlugin()).toThrow('mongoose-aes-encryption: options.key is required');
    });

    it('tests that createAESPlugin throws for an invalid algorithm', () => {
        expect(() => createAESPlugin({ key: testKey, algorithm: 'fake-algo' }))
            .toThrow('mongoose-aes-encryption: invalid algorithm \'fake-algo\'');
    });

    it('tests that createAESPlugin returns a valid Mongoose plugin function', () => {
        const plugin = createAESPlugin({ key: testKey });
        expect(plugin).toEqual(expect.any(Function));
    });

    it('tests that aes-256-gcm is used as the default algorithm', async () => {
        const plugin = createAESPlugin({ key: testKey });
        const schema = new mongoose.Schema({ label: { type: String, encrypted: true } });
        schema.plugin(plugin);
        const Item = mongoose.model('Item', schema);
        const item = new Item({ label: 'test' });
        const saved = await item.save();
        const lean = await Item.findById(saved._id).lean();
        // AES-256-GCM produces 3 pipe-separated parts: iv|ciphertext|authTag
        expect(lean.label.split('|').length).toStrictEqual(3);
        await Item.deleteMany();
    });

    it('tests that aes-256-cbc is accepted as algorithm', async () => {
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-cbc' });
        const schema = new mongoose.Schema({ label: { type: String, encrypted: true } });
        schema.plugin(plugin);
        const Widget = mongoose.model('Widget', schema);
        const widget = new Widget({ label: 'test' });
        const saved = await widget.save();
        const lean = await Widget.findById(saved._id).lean();
        // AES-256-CBC produces 2 pipe-separated parts: iv|ciphertext
        expect(lean.label.split('|').length).toStrictEqual(2);
        await Widget.deleteMany();
    });

});
