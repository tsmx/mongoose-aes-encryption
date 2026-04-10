const { parseKey, encrypt, decrypt } = require('../lib/crypto');

describe('mongoose-aes-encryption crypto test suite', () => {

    const testKeyHex = '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f';
    const testKeyRaw = '0123456789qwertzuiopasdfghjklyxc';
    const testString = 'Test123$ üöä';
    const hexReg = /^[0-9A-F]*$/i;

    it('tests parseKey with a 32-character raw string key', () => {
        const buf = parseKey(testKeyRaw);
        expect(buf).toBeInstanceOf(Buffer);
        expect(buf.length).toStrictEqual(32);
    });

    it('tests parseKey with a 64-character hex string key', () => {
        const buf = parseKey(testKeyHex);
        expect(buf).toBeInstanceOf(Buffer);
        expect(buf.length).toStrictEqual(32);
    });

    it('tests parseKey throws when key is missing', () => {
        expect(() => parseKey(null)).toThrow('mongoose-aes-encryption: key is required');
        expect(() => parseKey(undefined)).toThrow('mongoose-aes-encryption: key is required');
        expect(() => parseKey('')).toThrow('mongoose-aes-encryption: key is required');
    });

    it('tests parseKey throws when key has invalid length', () => {
        expect(() => parseKey('tooshort')).toThrow('mongoose-aes-encryption: key must be 32 bytes (raw string) or 64 hex characters');
    });

    it('tests encrypt and decrypt round-trip with GCM and hex key', () => {
        const cipher = encrypt(testString, { key: testKeyHex, algorithm: 'aes-256-gcm' });
        const parts = cipher.split('|');
        expect(parts.length).toStrictEqual(3);
        parts.forEach(part => expect(hexReg.test(part)).toStrictEqual(true));
        expect(decrypt(cipher, { key: testKeyHex })).toStrictEqual(testString);
    });

    it('tests encrypt and decrypt round-trip with CBC and hex key', () => {
        const cipher = encrypt(testString, { key: testKeyHex, algorithm: 'aes-256-cbc' });
        const parts = cipher.split('|');
        expect(parts.length).toStrictEqual(2);
        parts.forEach(part => expect(hexReg.test(part)).toStrictEqual(true));
        expect(decrypt(cipher, { key: testKeyHex })).toStrictEqual(testString);
    });

    it('tests encrypt and decrypt round-trip with CBC and raw 32-char key', () => {
        const cipher = encrypt(testString, { key: testKeyRaw, algorithm: 'aes-256-cbc' });
        const parts = cipher.split('|');
        expect(parts.length).toStrictEqual(2);
        expect(decrypt(cipher, { key: testKeyRaw })).toStrictEqual(testString);
    });

    it('tests encrypt returns null for null input when passNull is true', () => {
        expect(encrypt(null, { key: testKeyHex, passNull: true })).toStrictEqual(null);
    });

    it('tests encrypt throws for null input when passNull is false', () => {
        expect(() => encrypt(null, { key: testKeyHex, passNull: false })).toThrow('mongoose-aes-encryption: encrypt input must not be null');
    });

    it('tests encrypt throws for null input when passNull is omitted', () => {
        expect(() => encrypt(null, { key: testKeyHex })).toThrow('mongoose-aes-encryption: encrypt input must not be null');
    });

    it('tests decrypt returns null for null input when passNull is true', () => {
        expect(decrypt(null, { key: testKeyHex, passNull: true })).toStrictEqual(null);
    });

    it('tests decrypt throws for null input when passNull is false', () => {
        expect(() => decrypt(null, { key: testKeyHex, passNull: false })).toThrow('mongoose-aes-encryption: decrypt input must not be null');
    });

    it('tests encrypt throws for unknown algorithm', () => {
        expect(() => encrypt(testString, { key: testKeyHex, algorithm: 'aes-256-ecb' })).toThrow('mongoose-aes-encryption: unknown algorithm \'aes-256-ecb\'');
    });

    it('tests decrypt throws when ciphertext has been tampered with', () => {
        const cipher = encrypt(testString, { key: testKeyHex, algorithm: 'aes-256-gcm' });
        const parts = cipher.split('|');
        parts[2] = 'ff'.repeat(16);
        const tampered = parts.join('|');
        expect(() => decrypt(tampered, { key: testKeyHex })).toThrow('mongoose-aes-encryption: decryption failed');
    });

});
