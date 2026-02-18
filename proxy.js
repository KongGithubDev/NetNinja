require('dotenv').config();
const http = require('http');
const net = require('net');
const url = require('url');
const dns = require('dns');

dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']);

const PORT = process.env.PORT || 8080;

// GFN / NVIDIA domains → DIRECT (not proxied)
const directPatterns = [
    /\.geforcenow\.nvidiagrid\.net$/i,
    /\.nvidia\.com$/i,
    /\.nvidiagrid\.net$/i,
];

function isDirect(hostname) {
    return directPatterns.some(p => p.test(hostname));
}

let stats = { proxy: 0, direct: 0, total: 0 };

function resolveHost(hostname) {
    return new Promise((resolve, reject) => {
        if (net.isIP(hostname)) return resolve(hostname);
        dns.resolve4(hostname, (err, addresses) => {
            if (err || !addresses || addresses.length === 0) {
                dns.lookup(hostname, { family: 4 }, (err2, address) => {
                    if (err2 || !address) return reject(err2 || new Error('DNS failed'));
                    resolve(address);
                });
                return;
            }
            resolve(addresses[0]);
        });
    });
}

function generatePAC(proxyHost) {
    const directRules = [
        'geforcenow.nvidiagrid.net',
        'nvidia.com',
        'nvidiagrid.net',
    ].map(d => `    if (dnsDomainIs(host, "${d}")) return "DIRECT";`).join('\n');

    return `function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*") ||
        host == "127.0.0.1" ||
        host == "localhost") {
        return "DIRECT";
    }
${directRules}
    return "PROXY ${proxyHost}; DIRECT";
}
`;
}

const server = http.createServer((req, res) => {
    // PAC File
    if (req.url === '/proxy.pac') {
        const proxyHost = req.headers.host || `localhost:${PORT}`;
        res.writeHead(200, {
            'Content-Type': 'application/x-ns-proxy-autoconfig',
            'Cache-Control': 'no-cache',
        });
        res.end(generatePAC(proxyHost));
        console.log(`[PAC] Served to ${req.socket.remoteAddress}`);
        return;
    }

    // Status Page
    if (req.url === '/status') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#121212;color:#e0e0e0">
            <h1 style="color:#4caf50">✅ NetNinja Proxy Active</h1>
            <p style="font-size:1.2em">PAC URL: <code>http://${req.headers.host}/proxy.pac</code></p>
            <hr style="border-color:#333">
            <p>Proxy Requests: <b>${stats.proxy}</b></p>
            <p>Direct Requests: <b>${stats.direct}</b></p>
            <p>Total: <b>${stats.total}</b></p>
        </body></html>`);
        return;
    }

    // Health Check
    if (req.url === '/' || req.url === '/healthz') {
        res.writeHead(200);
        res.end('NetNinja Proxy: Active');
        return;
    }

    // HTTP Proxy
    const parsedUrl = url.parse(req.url);
    if (!parsedUrl.hostname) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
    }

    stats.total++;
    if (isDirect(parsedUrl.hostname)) stats.direct++;
    else stats.proxy++;

    resolveHost(parsedUrl.hostname).then(ip => {
        const proxyReq = http.request({
            host: ip,
            port: parsedUrl.port || 80,
            path: parsedUrl.path,
            method: req.method,
            headers: { ...req.headers, 'Host': parsedUrl.hostname },
        }, (proxyRes) => {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
        });

        req.pipe(proxyReq);
        proxyReq.on('error', (e) => {
            console.error('HTTP Proxy Error:', e.message);
            res.end();
        });
    }).catch(err => {
        console.error('DNS Error (HTTP):', err.message);
        res.writeHead(502);
        res.end('DNS Resolution Failed');
    });
});

// HTTPS CONNECT
server.on('connect', (req, clientSocket, head) => {
    const { port, hostname } = url.parse(`//${req.url}`, false, true);
    if (!hostname || !port) {
        clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
    }

    stats.total++;
    if (isDirect(hostname)) stats.direct++;
    else stats.proxy++;

    console.log(`Tunneling: ${hostname}:${port}`);

    clientSocket.on('error', () => { if (serverSocket) serverSocket.end(); });

    let serverSocket;
    resolveHost(hostname).then(ip => {
        try {
            serverSocket = net.connect(port, ip, () => {
                clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                serverSocket.write(head);
                serverSocket.pipe(clientSocket);
                clientSocket.pipe(serverSocket);
            });

            clientSocket.setNoDelay(true);
            serverSocket.setNoDelay(true);

            serverSocket.on('error', () => {
                if (!clientSocket.destroyed) clientSocket.end();
            });
        } catch (err) {
            clientSocket.end();
        }
    }).catch(err => {
        console.error('DNS Error (CONNECT):', err.message);
        clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    });
});

// Crash prevention
process.on('uncaughtException', (err) => {
    if (['ECONNRESET', 'EPIPE', 'ETIMEDOUT'].includes(err.code)) return;
    console.error('UNCAUGHT EXCEPTION:', err);
});

server.on('clientError', (err, socket) => {
    if (err.code === 'ECONNRESET' || !socket.writable) return;
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n=== NetNinja Proxy Running on Port ${PORT} ===`);
    console.log(`DNS: Google 8.8.8.8 / Cloudflare 1.1.1.1`);
    console.log(`PAC: http://localhost:${PORT}/proxy.pac`);
    console.log(`Status: http://localhost:${PORT}/status`);
    console.log('==============================================\n');
});
