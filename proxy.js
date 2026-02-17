require('dotenv').config();
const http = require('http');
const net = require('net');
const url = require('url');

const PORT = process.env.PORT || 8080;

// Security: Load Users
const users = new Map();

// 1. Load from PROXY_USERS (user1:pass1,user2:pass2)
if (process.env.PROXY_USERS) {
    process.env.PROXY_USERS.split(',').forEach(pair => {
        const [u, p] = pair.trim().split(':');
        if (u && p) users.set(u, p);
    });
}
// 2. Load legacy single user (fallback)
if (process.env.PROXY_USER && process.env.PROXY_PASS) {
    users.set(process.env.PROXY_USER, process.env.PROXY_PASS);
}

if (users.size === 0) {
    console.warn("WARNING: No users configured! Proxy is open or broken.");
} else {
    console.log(`Loaded ${users.size} users.`);
}

function checkAuth(req, res) {
    const auth = req.headers['proxy-authorization'];
    if (!auth) return false;

    // auth is "Basic base64string"
    const [scheme, credentials] = auth.split(' ');
    if (scheme !== 'Basic' || !credentials) return false;

    const [user, pass] = Buffer.from(credentials, 'base64').toString().split(':');
    return users.has(user) && users.get(user) === pass;
}

function requestAuth(res) {
    res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Internet Access"' });
    res.end('Proxy Authentication Required');
}

const server = http.createServer((req, res) => {
    // Render.com Health Check (Bypass Auth)
    if (req.url === '/healthz' || req.url === '/') {
        res.writeHead(200);
        res.end('Proxy Active');
        return;
    }

    if (!checkAuth(req, res)) {
        return requestAuth(res);
    }

    // Handle standard HTTP requests
    const parsedUrl = url.parse(req.url);

    if (!parsedUrl.hostname) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid Request: Please configure this as a Proxy Server in your Wi-Fi settings.');
        return;
    }

    const proxyReq = http.request({
        host: parsedUrl.hostname,
        port: parsedUrl.port || 80,
        path: parsedUrl.path,
        method: req.method,
        headers: req.headers
    }, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });

    req.pipe(proxyReq);

    proxyReq.on('error', (e) => {
        console.error('HTTP Proxy Error:', e.message);
        res.end();
    });
});

// Handle HTTPS CONNECT Tunneling (The most important part for Y8/Modern Web)
server.on('connect', (req, clientSocket, head) => {
    if (!checkAuth(req)) {
        clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\n' +
            'Proxy-Authenticate: Basic realm="Node Proxy"\r\n' +
            '\r\n');
        clientSocket.end();
        return;
    }

    const { port, hostname } = url.parse(`//${req.url}`, false, true);

    if (!hostname || !port) {
        clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
    }

    console.log(`Tunneling: ${hostname}:${port}`);

    // 1. Error handling MUST be attached immediately to clientSocket
    clientSocket.on('error', (e) => {
        if (!serverSocket || serverSocket.destroyed) return;
        serverSocket.end();
    });

    let serverSocket;
    try {
        serverSocket = net.connect(port, hostname, () => {
            // Standard Tunnel Response (Stealth Mode)
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

            serverSocket.write(head);
            serverSocket.pipe(clientSocket);
            clientSocket.pipe(serverSocket);
        });

        // Optimization: Disable Nagle's algorithm for lower latency (Y8/Gaming)
        clientSocket.setNoDelay(true);
        serverSocket.setNoDelay(true);

        // 2. Error handling MUST be attached immediately to serverSocket
        serverSocket.on('error', (e) => {
            if (!clientSocket.destroyed) clientSocket.end();
        });
    } catch (err) {
        clientSocket.end();
    }
});

// Prevent crashes from random socket errors
process.on('uncaughtException', (err) => {
    if (err.code === 'ECONNRESET' || err.code === 'EPIPE' || err.code === 'ETIMEDOUT') {
        // These are normal network disconnects, ignore them
        return;
    }
    console.error('UNCAUGHT EXCEPTION:', err);
});

server.on('clientError', (err, socket) => {
    if (err.code === 'ECONNRESET' || !socket.writable) {
        return;
    }
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n=== HTTP Proxy Server Running on Port ${PORT} ===`);
    console.log(`Please configure your iPad Wi-Fi Proxy to:`);
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                console.log(`SERVER: ${net.address}`);
                console.log(`PORT:   ${PORT}`);
            }
        }
    }
    console.log('==============================================\n');
});
