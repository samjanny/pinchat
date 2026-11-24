'use strict';

// Minimal in-memory IndexedDB for Node tests: open/upgrade, one transaction
// per call, get/put/delete and a forward cursor. Requests and transaction
// completion are delivered asynchronously, as in a browser. Values are kept
// by reference (no structured clone), which is enough for CryptoKey handles.
function createFakeIndexedDB() {
    const databases = new Map();
    const later = (fn) => setTimeout(fn, 0);

    function makeDb(entry) {
        return {
            objectStoreNames: { contains: (name) => entry.stores.has(name) },
            createObjectStore(name) { entry.stores.set(name, new Map()); },
            close() {},
            transaction(storeName, mode) {
                const data = entry.stores.get(storeName);
                if (!data) throw new Error('NotFoundError');
                const writable = mode === 'readwrite';
                let pending = 0;
                let done = false;
                const tx = { oncomplete: null, onerror: null, onabort: null };
                const settle = () => later(() => {
                    if (pending === 0 && !done) {
                        done = true;
                        if (tx.oncomplete) tx.oncomplete();
                    }
                });
                const op = (fn) => {
                    const req = { result: undefined, onsuccess: null, onerror: null };
                    pending++;
                    later(() => {
                        req.result = fn();
                        pending--;
                        if (req.onsuccess) req.onsuccess();
                        settle();
                    });
                    return req;
                };
                const requireWritable = () => {
                    if (!writable) throw new Error('ReadOnlyError');
                };
                tx.objectStore = () => ({
                    get: (key) => op(() => data.get(key)),
                    put: (value, key) => {
                        requireWritable();
                        return op(() => { data.set(key, value); return key; });
                    },
                    delete: (key) => {
                        requireWritable();
                        return op(() => { data.delete(key); });
                    },
                    openCursor: () => {
                        const keys = [...data.keys()];
                        let index = 0;
                        const req = { result: null, onsuccess: null, onerror: null };
                        pending++;
                        const step = () => later(() => {
                            while (index < keys.length && !data.has(keys[index])) index++;
                            if (index < keys.length) {
                                const key = keys[index];
                                req.result = {
                                    key,
                                    value: data.get(key),
                                    delete: () => { requireWritable(); data.delete(key); },
                                    continue: () => { index++; step(); },
                                };
                            } else {
                                req.result = null;
                                pending--;
                            }
                            if (req.onsuccess) req.onsuccess();
                            if (req.result === null) settle();
                        });
                        step();
                        return req;
                    },
                });
                settle();
                return tx;
            },
        };
    }

    return {
        databases,
        open(name) {
            const req = {
                result: null, onsuccess: null, onerror: null,
                onupgradeneeded: null, onblocked: null,
            };
            later(() => {
                let entry = databases.get(name);
                const created = !entry;
                if (created) {
                    entry = { stores: new Map() };
                    databases.set(name, entry);
                }
                req.result = makeDb(entry);
                if (created && req.onupgradeneeded) req.onupgradeneeded();
                if (req.onsuccess) req.onsuccess();
            });
            return req;
        },
        // Test access to the raw contents of one object store.
        store(dbName, storeName) {
            const entry = databases.get(dbName);
            return entry ? entry.stores.get(storeName) : undefined;
        },
    };
}

module.exports = { createFakeIndexedDB };
