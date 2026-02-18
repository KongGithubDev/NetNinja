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

// Colors
const C = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    red: '\x1b[31m',
    gray: '\x1b[90m',
    magenta: '\x1b[35m',
};

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

const server = http.createServer((req, res) => {
    // --- PAC File ---
    if (req.url === '/proxy.pac') {
        const proxyHost = req.headers.host || `localhost:${PORT}`;
        const pac = generatePAC(proxyHost);
        res.writeHead(200, {
            'Content-Type': 'application/x-ns-proxy-autoconfig',
            'Cache-Control': 'no-cache',
        });
        res.end(pac);
        console.log(`${C.cyan}[PAC]${C.reset} Served to ${req.socket.remoteAddress}`);
        return;
    }

    // --- Test Page ---
    if (req.url === '/test') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body style="font-family:sans-serif;text-align:center;padding:50px">
            <h1 style="color:green">✅ Proxy Reachable!</h1>
            <p>PAC URL: <b>http://${req.headers.host}/proxy.pac</b></p>
            <p><b>Stats:</b> PROXY: ${stats.proxy} | DIRECT: ${stats.direct} | Total: ${stats.total}</p>
        </body></html>`);
        return;
    }

    // --- Health Check ---
    if (req.url === '/' || req.url === '/healthz') {
        res.writeHead(200);
        res.end(`NetNinja Debug Proxy\nPROXY: ${stats.proxy} | DIRECT: ${stats.direct} | Total: ${stats.total}`);
        return;
    }

    // --- HTTP Proxy ---
    const parsedUrl = url.parse(req.url);
    if (!parsedUrl.hostname) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
    }

    stats.total++;

    const hostname = parsedUrl.hostname;
    const tag = isDirect(hostname) ? `${C.magenta}[DIRECT→]` : `${C.green}[PROXY→]`;
    const label = isDirect(hostname) ? 'DIRECT' : 'PROXY';

    if (isDirect(hostname)) stats.direct++;
    else stats.proxy++;

    console.log(`${tag}${C.reset} ${C.yellow}${req.method}${C.reset} ${hostname}${parsedUrl.path} ${C.gray}← ${req.socket.remoteAddress}${C.reset}`);

    resolveHost(hostname).then(ip => {
        console.log(`  ${C.gray}DNS: ${hostname} → ${ip}${C.reset}`);

        const proxyReq = http.request({
            host: ip,
            port: parsedUrl.port || 80,
            path: parsedUrl.path,
            method: req.method,
            headers: { ...req.headers, 'Host': hostname },
        }, (proxyRes) => {
            console.log(`  ${tag}${C.reset} ${hostname} → ${C.cyan}${proxyRes.statusCode}${C.reset} [${label}]`);
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
        });

        req.pipe(proxyReq);
        proxyReq.on('error', (e) => {
            console.log(`  ${C.red}[ERR]${C.reset} ${hostname}: ${e.message}`);
            res.end();
        });
    }).catch(err => {
        console.log(`  ${C.red}[DNS ERR]${C.reset} ${hostname}: ${err.message}`);
        res.writeHead(502);
        res.end('DNS Failed');
    });
});

// --- HTTPS CONNECT ---
server.on('connect', (req, clientSocket, head) => {
    const { port, hostname } = url.parse(`//${req.url}`, false, true);
    if (!hostname || !port) {
        clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
    }

    stats.total++;

    const tag = isDirect(hostname) ? `${C.magenta}[DIRECT↔]` : `${C.cyan}[PROXY↔]`;
    const label = isDirect(hostname) ? 'DIRECT' : 'PROXY';

    if (isDirect(hostname)) stats.direct++;
    else stats.proxy++;

    console.log(`${tag}${C.reset} CONNECT ${C.yellow}${hostname}:${port}${C.reset} ${C.gray}← ${clientSocket.remoteAddress}${C.reset} [${label}]`);

    let serverSocket;
    resolveHost(hostname).then(ip => {
        console.log(`  ${C.gray}DNS: ${hostname} → ${ip}${C.reset}`);

        serverSocket = net.connect(port, ip, () => {
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            serverSocket.write(head);
            serverSocket.pipe(clientSocket);
            clientSocket.pipe(serverSocket);
            console.log(`  ${tag}${C.reset} ${hostname} ${C.green}TUNNEL OK${C.reset} [${label}]`);
        });

        clientSocket.setNoDelay(true);
        serverSocket.setNoDelay(true);

        serverSocket.on('error', () => { if (!clientSocket.destroyed) clientSocket.end(); });
        clientSocket.on('error', () => { if (serverSocket) serverSocket.end(); });

        serverSocket.on('close', () => {
            console.log(`  ${C.gray}[CLOSED] ${hostname}:${port} [${label}]${C.reset}`);
        });
    }).catch(err => {
        console.log(`  ${C.red}[ERR]${C.reset} CONNECT ${hostname}: ${err.message}`);
        clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    });
});

// --- PAC Generator ---
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

// Crash prevention
process.on('uncaughtException', (err) => {
    if (['ECONNRESET', 'EPIPE', 'ETIMEDOUT'].includes(err.code)) return;
    console.error(`${C.red}UNCAUGHT:${C.reset}`, err);
});

server.on('clientError', (err, socket) => {
    if (err.code === 'ECONNRESET' || !socket.writable) return;
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, '0.0.0.0', () => {
    console.log();
    console.log(`=== NetNinja ${C.yellow}DEBUG${C.reset} Proxy on Port ${PORT} ===`);
    console.log(`DNS: Google 8.8.8.8 / Cloudflare 1.1.1.1`);
    console.log(`PAC: http://localhost:${PORT}/proxy.pac`);
    console.log(`Test: http://localhost:${PORT}/test`);
    console.log();
    console.log(`${C.green}[PROXY→]${C.reset} = ผ่าน Proxy (bypass DNS filter)`);
    console.log(`${C.magenta}[DIRECT→]${C.reset} = ถูก PAC กำหนดให้ไปตรง (เช่น GFN)`);
    console.log(`${C.cyan}[PROXY↔]${C.reset} = HTTPS tunnel ผ่าน Proxy`);
    console.log(`${C.magenta}[DIRECT↔]${C.reset} = HTTPS tunnel ที่ PAC ให้ไปตรง`);
    console.log('==============================================');
    console.log();
});
