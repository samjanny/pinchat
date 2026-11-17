'use strict';

/**
 * CONNECT proxy for the Firefox runs.
 *
 * Firefox has no switch to resolve a host name to another address, so the
 * browser under test is given this proxy instead. It tunnels the host names
 * under test to the local hostile server, lets the extension reach the
 * release host for its signed manifest, and refuses everything else, so a
 * test run cannot touch the real site or anything unrelated.
 */

const net = require('net');

function startProxy({ localHosts, localPort, passthroughHosts = [] }) {
    const refused = [];
    const server = net.createServer((client) => {
        client.once('data', (head) => {
            const line = head.toString('latin1').split('\r\n')[0];
            const match = /^CONNECT ([^:\s]+):(\d+) HTTP\/1\.[01]$/.exec(line);
            const fail = () => {
                refused.push(line.slice(0, 120));
                client.end('HTTP/1.1 403 Forbidden\r\n\r\n');
            };
            if (!match) return fail();
            const [, host, port] = match;
            let target = null;
            if (localHosts.includes(host)) target = { host: '127.0.0.1', port: localPort };
            else if (passthroughHosts.includes(host) && port === '443') target = { host, port: 443 };
            if (!target) return fail();
            const upstream = net.connect(target.port, target.host, () => {
                client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                upstream.pipe(client);
                client.pipe(upstream);
            });
            upstream.on('error', () => client.destroy());
            client.on('error', () => upstream.destroy());
            return undefined;
        });
        client.on('error', () => {});
    });
    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve({
            port: server.address().port,
            refused,
            close: () => server.close(),
        }));
    });
}

module.exports = { startProxy };
