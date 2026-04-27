const { parseKey, encrypt, decrypt, deriveSearchKey, hashForSearch } = require('./lib/crypto');

const allowedAlgorithms = ['aes-256-gcm', 'aes-256-cbc'];

function makeGetterSetter(originalType, parsedKey, algorithm, isArray) {
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
                return v.map(elem => elem == null ? elem : fromString(decrypt(elem, { key: parsedKey, passNull: true })));
            }
            const decrypted = decrypt(v, { key: parsedKey, passNull: true });
            return fromString(decrypted);
        },
        set(v) {
            if (v === null || v === undefined) return v;
            if (isArray && Array.isArray(v)) {
                return v.map(elem => elem == null ? elem : encrypt(toString(elem), { key: parsedKey, passNull: true, algorithm }));
            }
            return encrypt(toString(v), { key: parsedKey, passNull: true, algorithm });
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
    const parsedKey = parseKey(key);
    const searchKey = deriveSearchKey(parsedKey);

    return function encryptedPlugin(schema) {
        const pathsToRewrite = [];
        const searchablePaths = [];

        schema.eachPath((pathname, schemaType) => {
            if (schemaType.options && schemaType.options.encrypted === true) {
                const rawType = schemaType.options.type;
                const isArray = Array.isArray(rawType) && rawType.length === 1;
                const isSearchable = schemaType.options.searchable === true;
                if (isArray) {
                    pathsToRewrite.push({ pathname, originalType: rawType[0], isArray: true, isSearchable });
                } else {
                    pathsToRewrite.push({ pathname, originalType: rawType, isArray: false, isSearchable });
                }
                if (isSearchable) {
                    searchablePaths.push({ pathname, originalType: isArray ? rawType[0] : rawType, isArray });
                }
            }
        });

        for (const { pathname, originalType, isArray } of pathsToRewrite) {
            const { get, set } = makeGetterSetter(originalType, parsedKey, algorithm, isArray);
            const existingOptions = schema.path(pathname).options;
            const newOptions = Object.assign({}, existingOptions, {
                type: schema.constructor.Types.Mixed,
                get,
                set
            });
            schema.path(pathname, newOptions);
        }

        // Add __search_<fieldname> shadow fields and populate them on save
        if (searchablePaths.length > 0) {
            for (const { pathname } of searchablePaths) {
                const searchFieldName = `__search_${pathname}`;
                if (!schema.path(searchFieldName)) {
                    schema.add({ [searchFieldName]: { type: String, default: null } });
                }
            }

            schema.pre('save', function() {
                for (const { pathname, originalType, isArray } of searchablePaths) {
                    const searchFieldName = `__search_${pathname}`;
                    const value = this[pathname];
                    if (value === null || value === undefined) {
                        this[searchFieldName] = null;
                        continue;
                    }
                    if (isArray && Array.isArray(value)) {
                        // For array fields: hash each non-null element, join with '|'
                        this[searchFieldName] = value
                            .map(elem => elem == null ? '' : hashForSearch(toStringForType(originalType, elem), searchKey))
                            .join('|');
                    } else {
                        this[searchFieldName] = hashForSearch(toStringForType(originalType, value), searchKey);
                    }
                }
            });
        }
    };
};

function toStringForType(originalType, v) {
    if (originalType === Date) {
        return new Date(v).toISOString();
    }
    return String(v);
}

module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;

/**
 * Produces the search hash for a given plaintext value and key, matching
 * exactly what the plugin stores in __search_<fieldname> on save.
 * Use the returned string as the query value in find({ __search_<field>: result }).
 *
 * @param {string|number|boolean|Date} value  Plaintext value to hash
 * @param {object} options
 * @param {string} options.key  The same 64-char hex key passed to createAESPlugin
 * @returns {string}  64-character hex HMAC-SHA-256 digest
 */
module.exports.encryptForSearch = function encryptForSearch(value, options) {
    if (!options || !options.key) {
        throw new Error('mongoose-aes-encryption: options.key is required');
    }
    const sk = deriveSearchKey(parseKey(options.key));
    if (value instanceof Date) {
        return hashForSearch(value.toISOString(), sk);
    }
    return hashForSearch(String(value), sk);
};
