const mongoose = require('mongoose');
const { decrypt } = require('../mongoose-aes-encryption');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createAESPlugin = require('../mongoose-aes-encryption');

describe('mongoose-aes-encryption mixed scalar and array schema test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Listing = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-complex-mixed' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            title: { type: String, encrypted: true },
            price: { type: Number, encrypted: true },
            tags: { type: [String], encrypted: true },
            ratings: { type: [Number], encrypted: true }
        });
        schema.plugin(plugin);
        Listing = mongoose.model('Listing', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testListing = new Listing();
        testListing.id = 'id-test';
        testListing.title = 'Test Listing';
        testListing.price = 99.99;
        testListing.tags = ['sale', 'new'];
        testListing.ratings = [4.5, 3.0];
        await testListing.save();
    });

    afterEach(async () => {
        await Listing.deleteMany();
    });

    it('tests a successful document creation with mixed scalar and array encrypted fields', async () => {
        const listing = new Listing();
        listing.id = 'id-1';
        listing.title = 'My Listing';
        listing.price = 49.95;
        listing.tags = ['featured', 'trending'];
        listing.ratings = [5.0, 4.0, 3.5];
        const saved = await listing.save();
        expect(saved.title).toStrictEqual('My Listing');
        expect(saved.price).toStrictEqual(49.95);
        expect(saved.tags).toStrictEqual(['featured', 'trending']);
        expect(saved.ratings).toStrictEqual([5.0, 4.0, 3.5]);
        const lean = await Listing.findById(saved._id).lean();
        expect(lean.title.split('|').length).toStrictEqual(3);
        expect(lean.price.split('|').length).toStrictEqual(3);
        lean.tags.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
        lean.ratings.forEach(elem => expect(elem.split('|').length).toStrictEqual(3));
    });

    it('tests a successful document update of both scalar and array encrypted fields', async () => {
        const listing = await Listing.findOne({ id: 'id-test' });
        expect(listing.title).toStrictEqual('Test Listing');
        expect(listing.tags).toStrictEqual(['sale', 'new']);
        listing.title = 'Updated Listing';
        listing.tags = ['clearance'];
        await listing.save();
        const updated = await Listing.findOne({ id: 'id-test' });
        expect(updated.title).toStrictEqual('Updated Listing');
        expect(updated.price).toStrictEqual(99.99);
        expect(updated.tags).toStrictEqual(['clearance']);
        expect(updated.ratings).toStrictEqual([4.5, 3.0]);
    });

    it('tests null passthrough for both scalar and array encrypted fields', async () => {
        const listing = new Listing();
        listing.id = 'id-null';
        listing.title = null;
        listing.price = 10.0;
        listing.tags = null;
        listing.ratings = [1.0];
        const saved = await listing.save();
        expect(saved.title).toStrictEqual(null);
        expect(saved.tags).toStrictEqual(null);
        const retrieved = await Listing.findOne({ id: 'id-null' });
        expect(retrieved.title).toStrictEqual(null);
        expect(retrieved.price).toStrictEqual(10.0);
        expect(retrieved.tags).toStrictEqual(null);
        expect(retrieved.ratings).toStrictEqual([1.0]);
    });

});

describe('mongoose-aes-encryption inline nested sub-document test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Location = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-complex-nested' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            address: {
                street: { type: String, encrypted: true },
                city: { type: String }
            }
        });
        schema.plugin(plugin);
        Location = mongoose.model('Location', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testLocation = new Location();
        testLocation.id = 'id-test';
        testLocation.address = { street: '123 Main St', city: 'Springfield' };
        await testLocation.save();
    });

    afterEach(async () => {
        await Location.deleteMany();
    });

    it('tests a successful document creation with an inline nested encrypted field', async () => {
        const location = new Location();
        location.id = 'id-1';
        location.address = { street: '456 Oak Ave', city: 'Shelbyville' };
        const saved = await location.save();
        expect(saved.address.street).toStrictEqual('456 Oak Ave');
        expect(saved.address.city).toStrictEqual('Shelbyville');
        const lean = await Location.findById(saved._id).lean();
        expect(lean.address.street).not.toStrictEqual('456 Oak Ave');
        expect(lean.address.street.split('|').length).toStrictEqual(3);
        expect(lean.address.city).toStrictEqual('Shelbyville');
    });

    it('tests a successful document update of an inline nested encrypted field', async () => {
        const location = await Location.findOne({ id: 'id-test' });
        expect(location.address.street).toStrictEqual('123 Main St');
        location.address.street = '789 Elm Rd';
        await location.save();
        const updated = await Location.findOne({ id: 'id-test' });
        expect(updated.address.street).toStrictEqual('789 Elm Rd');
        expect(updated.address.city).toStrictEqual('Springfield');
    });

    it('tests null passthrough for an inline nested encrypted field', async () => {
        const location = new Location();
        location.id = 'id-null';
        location.address = { street: null, city: 'Nowhere' };
        const saved = await location.save();
        expect(saved.address.street).toStrictEqual(null);
        expect(saved.address.city).toStrictEqual('Nowhere');
        const retrieved = await Location.findOne({ id: 'id-null' });
        expect(retrieved.address.street).toStrictEqual(null);
        expect(retrieved.address.city).toStrictEqual('Nowhere');
    });

    it('tests a successful manual decryption of an inline nested encrypted field from a lean query', async () => {
        const lean = await Location.findOne({ id: 'id-test' }).lean();
        expect(lean.address.street.split('|').length).toStrictEqual(3);
        expect(decrypt(lean.address.street, { key: testKey })).toStrictEqual('123 Main St');
        expect(lean.address.city).toStrictEqual('Springfield');
    });

});

describe('mongoose-aes-encryption separate sub-schema test suite', () => {

    const testKey = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';

    var mongoServer = null;
    var Employee = null;

    beforeAll(async () => {
        mongoServer = await MongoMemoryServer.create({ dbName: 'aes-encryption-complex-subschema' });
        await mongoose.connect(mongoServer.getUri());
        const plugin = createAESPlugin({ key: testKey, algorithm: 'aes-256-gcm' });
        const contactSchema = new mongoose.Schema({
            email: { type: String, encrypted: true },
            phone: { type: String }
        });
        contactSchema.plugin(plugin);
        const schema = new mongoose.Schema({
            id: { type: String, required: true },
            name: { type: String, encrypted: true },
            contacts: [contactSchema]
        });
        schema.plugin(plugin);
        Employee = mongoose.model('Employee', schema);
    });

    afterAll(async () => {
        await mongoose.connection.close();
        await mongoServer.stop();
    });

    beforeEach(async () => {
        const testEmployee = new Employee();
        testEmployee.id = 'id-test';
        testEmployee.name = 'Jane Doe';
        testEmployee.contacts = [
            { email: 'jane@example.com', phone: '555-1234' },
            { email: 'jane.doe@work.com', phone: '555-5678' }
        ];
        await testEmployee.save();
    });

    afterEach(async () => {
        await Employee.deleteMany();
    });

    it('tests a successful document creation with a separate encrypted sub-schema in an array', async () => {
        const employee = new Employee();
        employee.id = 'id-1';
        employee.name = 'John Smith';
        employee.contacts = [{ email: 'john@example.com', phone: '555-9999' }];
        const saved = await employee.save();
        expect(saved.name).toStrictEqual('John Smith');
        expect(saved.contacts[0].email).toStrictEqual('john@example.com');
        expect(saved.contacts[0].phone).toStrictEqual('555-9999');
        const lean = await Employee.findById(saved._id).lean();
        expect(lean.name.split('|').length).toStrictEqual(3);
        expect(lean.contacts[0].email.split('|').length).toStrictEqual(3);
        expect(lean.contacts[0].phone).toStrictEqual('555-9999');
    });

    it('tests a successful document update of a sub-schema array element encrypted field', async () => {
        const employee = await Employee.findOne({ id: 'id-test' });
        expect(employee.name).toStrictEqual('Jane Doe');
        expect(employee.contacts[0].email).toStrictEqual('jane@example.com');
        employee.contacts[0].email = 'updated@example.com';
        await employee.save();
        const updated = await Employee.findOne({ id: 'id-test' });
        expect(updated.contacts[0].email).toStrictEqual('updated@example.com');
        expect(updated.contacts[1].email).toStrictEqual('jane.doe@work.com');
    });

    it('tests a successful manual decryption of sub-schema encrypted fields from a lean query', async () => {
        const lean = await Employee.findOne({ id: 'id-test' }).lean();
        expect(lean.name.split('|').length).toStrictEqual(3);
        expect(decrypt(lean.name, { key: testKey })).toStrictEqual('Jane Doe');
        expect(lean.contacts[0].email.split('|').length).toStrictEqual(3);
        expect(decrypt(lean.contacts[0].email, { key: testKey })).toStrictEqual('jane@example.com');
        expect(lean.contacts[0].phone).toStrictEqual('555-1234');
    });

});
