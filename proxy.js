require('dotenv').config();
const http = require('http');
const net = require('net');
const url = require('url');
const dns = require('dns');

// Configure custom DNS (Google and Cloudflare)
dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']);

/**
 * Resolves a hostname to an IPv4 address using custom DNS servers.
 */
function resolveHost(hostname) {
    return new Promise((resolve, reject) => {
        if (net.isIP(hostname)) return resolve(hostname);
        dns.resolve4(hostname, (err, addresses) => {
            if (err || !addresses || addresses.length === 0) {
                dns.lookup(hostname, { family: 4 }, (err2, address) => {
                    if (err2 || !address) return reject(err2 || new Error('Host resolution failed'));
                    resolve(address);
                });
                return;
            }
            resolve(addresses[0]);
        });
    });
}

const PORT = process.env.PORT || 8080;

const server = http.createServer((req, res) => {
    // Render.com Health Check (Base route)
    if (req.url === '/healthz' || req.url === '/') {
        res.writeHead(200);
        res.end('NetNinja Proxy: Active (Open Mode)');
        return;
    }

    // Handle standard HTTP requests
    const parsedUrl = url.parse(req.url);

    if (!parsedUrl.hostname) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid Request: Please configure this as a Proxy Server in your Wi-Fi settings.');
        return;
    }

    // Resolve host using custom DNS
    resolveHost(parsedUrl.hostname).then(ip => {
        const proxyReq = http.request({
            host: ip,
            port: parsedUrl.port || 80,
            path: parsedUrl.path,
            method: req.method,
            headers: {
                ...req.headers,
                'Host': parsedUrl.hostname
            }
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

// Handle HTTPS CONNECT Tunneling
server.on('connect', (req, clientSocket, head) => {
    const { port, hostname } = url.parse(`//${req.url}`, false, true);

    if (!hostname || !port) {
        clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
    }

    console.log(`Tunneling: ${hostname}:${port}`);

    clientSocket.on('error', () => {
        if (serverSocket) serverSocket.end();
    });

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
    console.log(`\n=== NetNinja Open Proxy Running on Port ${PORT} ===`);
    console.log(`Security: Open Bypass (No Authentication Required)`);
    console.log(`DNS: Specialized (Google 8.8.8.8 / Cloudflare 1.1.1.1)`);
    console.log('==============================================\n');
});
