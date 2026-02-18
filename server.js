const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const puppeteer = require('puppeteer');
const path = require('path');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e8
});

const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

// --- Global Browser State ---
let globalBrowser;
let globalPage;
let globalCDP;
let isInitializing = false;

// Track connected sockets for high-performance broadcasting
const activeSockets = new Map(); // socket.id -> socket object

async function initBrowser() {
    if (globalBrowser || isInitializing) return;
    isInitializing = true;
    console.log('Initializing Persistent Global Browser (Y8 Optimized)...');

    try {
        globalBrowser = await puppeteer.launch({
            headless: "new",
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--window-size=1280,720',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--force-device-scale-factor=1' // Ensure 1:1 pixel mapping
            ]
        });

        globalPage = await globalBrowser.newPage();
        await globalPage.setViewport({ width: 854, height: 480 });
        await globalPage.goto('https://www.google.com');

        // Setup Shared CDP Screencasting
        globalCDP = await globalPage.target().createCDPSession();
        await globalCDP.send('Page.startScreencast', {
            format: 'webp',
            quality: 30, // Optimized for VPS network/latency
            everyNthFrame: 1
        });

        globalCDP.on('Page.screencastFrame', async ({ data, sessionId }) => {
            try {
                const buffer = Buffer.from(data, 'base64');
                // ULTRA Performance: Use a simple loop over a Map instead of fetchSockets()
                for (const [id, socket] of activeSockets) {
                    if (socket.isReady !== false) {
                        socket.isReady = false;
                        socket.emit('frame', buffer);
                    }
                }
                await globalCDP.send('Page.screencastFrameAck', { sessionId });
            } catch (err) { }
        });

        console.log('Global Browser Ready.');
    } catch (err) {
        console.error('Failed to init browser:', err);
    } finally {
        isInitializing = false;
    }
}

initBrowser();

io.on('connection', async (socket) => {
    console.log('User connected:', socket.id);
    socket.isReady = true; // Initialize readiness
    activeSockets.set(socket.id, socket);

    if (globalPage) {
        socket.emit('url-changed', globalPage.url());
    }

    socket.on('frame-ack', () => {
        socket.isReady = true;
    });

    socket.on('navigate', async (url) => {
        try {
            if (!url.startsWith('http')) url = 'https://' + url;
            await globalPage.goto(url);
        } catch (err) {
            console.error('Navigation error:', err);
        }
    });

    socket.on('mouse-event', async (data) => {
        try {
            if (!globalPage) return;
            const { type, x, y, button } = data;
            if (type === 'mousedown') await globalPage.mouse.move(x, y);
            if (type === 'mousedown') await globalPage.mouse.down({ button });
            if (type === 'mouseup') await globalPage.mouse.up({ button });
            if (type === 'mousemove') await globalPage.mouse.move(x, y);
            if (type === 'click') {
                await globalPage.mouse.move(x, y);
                await globalPage.mouse.click(x, y);
            }
        } catch (err) { }
    });

    socket.on('key-event', async (data) => {
        try {
            if (!globalPage) return;
            const { type, key } = data;
            if (type === 'keydown') await globalPage.keyboard.down(key);
            if (type === 'keyup') await globalPage.keyboard.up(key);
            if (type === 'keypress') await globalPage.keyboard.press(key);
        } catch (err) { }
    });

    socket.on('scroll', async (data) => {
        try {
            if (!globalPage) return;
            const { deltaX, deltaY } = data;
            await globalPage.mouse.wheel({ deltaX, deltaY });
        } catch (err) { }
    });

    socket.on('browser-control', async (action) => {
        try {
            if (!globalPage) return;
            if (action === 'back') await globalPage.goBack();
            if (action === 'forward') await globalPage.goForward();
            if (action === 'reload') await globalPage.reload();
        } catch (err) { }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        activeSockets.delete(socket.id);
    });
});

// Periodic URL sync
setInterval(() => {
    if (globalPage) {
        io.emit('url-changed', globalPage.url());
    }
}, 2000);

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running!`);
    console.log(`- Local: http://localhost:${PORT}`);

    const nets = os.networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                console.log(`- Network: http://${net.address}:${PORT}`);
            }
        }
    }
});
