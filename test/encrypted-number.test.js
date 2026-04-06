const mongoose = require('mongoose');
const sc = require('@tsmx/string-crypto');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption EncryptedNumber test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Product = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-number' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            price: { type: Number, encrypted: true },
            stock: { type: Number, encrypted: true }
        });
        schema.plugin(plugin);
        Product = mongoose.model('Product', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testProduct = new Product();
        testProduct.id = 'id-test';
        testProduct.price = 9.99;
        testProduct.stock = 42;
        await testProduct.save();
    });

    afterEach(async () => {
        await Product.deleteMany();
    });

    it('tests a successful document creation with a float value', async () => {
        const product = new Product();
        product.id = 'id-1';
        product.price = 19.95;
        product.stock = 100;
        const saved = await product.save();
        expect(saved).toBeDefined();
        expect(saved._id).toBeDefined();
        expect(saved.price).toStrictEqual(19.95);
        expect(saved.stock).toStrictEqual(100);
        const lean = await Product.findById(saved._id).lean();
        expect(typeof lean.price).toStrictEqual('string');
        expect(lean.price.split('|').length).toStrictEqual(3);
        expect(typeof lean.stock).toStrictEqual('string');
        expect(lean.stock.split('|').length).toStrictEqual(3);
    });

    it('tests that an integer round-trips as an integer', async () => {
        const product = new Product();
        product.id = 'id-int';
        product.price = 5;
        product.stock = 200;
        const saved = await product.save();
        expect(saved.price).toStrictEqual(5);
        expect(Number.isInteger(saved.price)).toStrictEqual(true);
        expect(saved.stock).toStrictEqual(200);
        expect(Number.isInteger(saved.stock)).toStrictEqual(true);
    });

    it('tests a successful document update', async () => {
        const product = await Product.findOne({ id: 'id-test' });
        expect(product).toBeDefined();
        expect(product.price).toStrictEqual(9.99);
        expect(product.stock).toStrictEqual(42);
        product.price = 12.50;
        await product.save();
        const updated = await Product.findOne({ id: 'id-test' });
        expect(updated.price).toStrictEqual(12.50);
        expect(updated.stock).toStrictEqual(42);
    });

    it('tests a successful document creation and retrieval with null values', async () => {
        const product = new Product();
        product.id = 'id-null';
        product.price = null;
        product.stock = 10;
        const saved = await product.save();
        expect(saved.price).toStrictEqual(null);
        expect(saved.stock).toStrictEqual(10);
        const retrieved = await Product.findOne({ id: 'id-null' });
        expect(retrieved.price).toStrictEqual(null);
        expect(retrieved.stock).toStrictEqual(10);
    });

    it('tests a successful manual decryption of a document from a lean query', async () => {
        const lean = await Product.findOne({ id: 'id-test' }).lean();
        expect(typeof lean.price).toStrictEqual('string');
        expect(typeof lean.stock).toStrictEqual('string');
        expect(parseFloat(sc.decrypt(lean.price, { key: testKey }))).toStrictEqual(9.99);
        expect(parseFloat(sc.decrypt(lean.stock, { key: testKey }))).toStrictEqual(42);
    });

});
