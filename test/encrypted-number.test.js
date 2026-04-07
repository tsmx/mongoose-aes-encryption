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

describe('mongoose-aes-encryption EncryptedNumber array test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Sensor = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-number-array' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            readings: { type: [Number], encrypted: true },
            scores: { type: [Number], encrypted: true }
        });
        schema.plugin(plugin);
        Sensor = mongoose.model('Sensor', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testSensor = new Sensor();
        testSensor.id = 'id-test';
        testSensor.readings = [1.1, 2.2, 3.3];
        testSensor.scores = [10, 20];
        await testSensor.save();
    });

    afterEach(async () => {
        await Sensor.deleteMany();
    });

    it('tests a successful document creation', async () => {
        const sensor = new Sensor();
        sensor.id = 'id-1';
        sensor.readings = [4.4, 5.5];
        sensor.scores = [100, 200, 300];
        const saved = await sensor.save();
        expect(saved).toBeDefined();
        expect(saved._id).toBeDefined();
        expect(saved.readings).toStrictEqual([4.4, 5.5]);
        expect(saved.scores).toStrictEqual([100, 200, 300]);
        const lean = await Sensor.findById(saved._id).lean();
        expect(Array.isArray(lean.readings)).toStrictEqual(true);
        lean.readings.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
        expect(Array.isArray(lean.scores)).toStrictEqual(true);
        lean.scores.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
    });

    it('tests a successful document update', async () => {
        const sensor = await Sensor.findOne({ id: 'id-test' });
        expect(sensor).toBeDefined();
        expect(sensor.readings).toStrictEqual([1.1, 2.2, 3.3]);
        expect(sensor.scores).toStrictEqual([10, 20]);
        sensor.readings = [9.9];
        await sensor.save();
        const updated = await Sensor.findOne({ id: 'id-test' });
        expect(updated.readings).toStrictEqual([9.9]);
        expect(updated.scores).toStrictEqual([10, 20]);
    });

    it('tests a successful document creation and retrieval with a null field', async () => {
        const sensor = new Sensor();
        sensor.id = 'id-null';
        sensor.readings = null;
        sensor.scores = [5];
        const saved = await sensor.save();
        expect(saved.readings).toStrictEqual(null);
        expect(saved.scores).toStrictEqual([5]);
        const retrieved = await Sensor.findOne({ id: 'id-null' });
        expect(retrieved.readings).toStrictEqual(null);
        expect(retrieved.scores).toStrictEqual([5]);
    });

    it('tests a successful document creation and retrieval with an empty array', async () => {
        const sensor = new Sensor();
        sensor.id = 'id-empty';
        sensor.readings = [];
        sensor.scores = [1];
        const saved = await sensor.save();
        expect(saved.readings).toStrictEqual([]);
        const retrieved = await Sensor.findOne({ id: 'id-empty' });
        expect(retrieved.readings).toStrictEqual([]);
        expect(retrieved.scores).toStrictEqual([1]);
    });

    it('tests a successful manual decryption of a document from a lean query', async () => {
        const lean = await Sensor.findOne({ id: 'id-test' }).lean();
        expect(Array.isArray(lean.readings)).toStrictEqual(true);
        lean.readings.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
        expect(lean.readings.map(elem => parseFloat(sc.decrypt(elem, { key: testKey })))).toStrictEqual([1.1, 2.2, 3.3]);
        expect(lean.scores.map(elem => parseFloat(sc.decrypt(elem, { key: testKey })))).toStrictEqual([10, 20]);
    });

});
