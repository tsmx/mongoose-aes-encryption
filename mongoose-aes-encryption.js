const sc = require('@tsmx/string-crypto');

const allowedAlgorithms = ['aes-256-gcm', 'aes-256-cbc'];

function makeGetterSetter(originalType, key, algorithm, isArray) {
    function toString(v) {
        if (originalType === Date) {
            return new Date(v).toISOString();
        }
        return String(v);
    }

    function fromString(v) {
        if (originalType === Number) {
            return parseFloat(v);
        }
        if (originalType === Date) {
            return new Date(v);
        }
        if (originalType === Boolean) {
            return v === 'true';
        }
        return v;
    }

    return {
        get(v) {
            if (v === null || v === undefined) return v;
            if (isArray && Array.isArray(v)) {
                return v.map(elem => elem == null ? elem : fromString(sc.decrypt(elem, { key, passNull: true })));
            }
            const decrypted = sc.decrypt(v, { key, passNull: true });
            return fromString(decrypted);
        },
        set(v) {
            if (v === null || v === undefined) return v;
            if (isArray && Array.isArray(v)) {
                return v.map(elem => elem == null ? elem : sc.encrypt(toString(elem), { key, passNull: true, algorithm }));
            }
            return sc.encrypt(toString(v), { key, passNull: true, algorithm });
        }
    };
}

module.exports = function createAESPlugin(options) {
    if (!options || !options.key) {
        throw new Error('mongoose-aes-encryption: options.key is required');
    }
    const algorithm = options.algorithm ?? 'aes-256-gcm';
    if (!allowedAlgorithms.includes(algorithm)) {
        throw new Error(`mongoose-aes-encryption: invalid algorithm '${algorithm}'. Allowed: ${allowedAlgorithms.join(', ')}`);
    }
    const key = options.key;

    return function encryptedPlugin(schema) {
        const pathsToRewrite = [];

        schema.eachPath((pathname, schemaType) => {
            if (schemaType.options && schemaType.options.encrypted === true) {
                const rawType = schemaType.options.type;
                if (Array.isArray(rawType) && rawType.length === 1) {
                    pathsToRewrite.push({ pathname, originalType: rawType[0], isArray: true });
                } else {
                    pathsToRewrite.push({ pathname, originalType: rawType, isArray: false });
                }
            }
        });

        for (const { pathname, originalType, isArray } of pathsToRewrite) {
            const { get, set } = makeGetterSetter(originalType, key, algorithm, isArray);
            const existingOptions = schema.path(pathname).options;
            const newOptions = Object.assign({}, existingOptions, {
                type: schema.constructor.Types.Mixed,
                get,
                set
            });
            schema.path(pathname, newOptions);
        }
    };
};
