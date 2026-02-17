const socket = io();

const canvas = document.getElementById('view-canvas');
const ctx = canvas.getContext('2d');
const loadingOverlay = document.getElementById('loading-overlay');
const urlInput = document.getElementById('url-input');
const backBtn = document.getElementById('back-btn');
const forwardBtn = document.getElementById('forward-btn');
const reloadBtn = document.getElementById('reload-btn');
const statusDiv = document.getElementById('status');

let viewportWidth = 1280;
let viewportHeight = 720;

// Set initial size
canvas.width = viewportWidth;
canvas.height = viewportHeight;

// Performance metrics
let frameCount = 0;
setInterval(() => {
    if (frameCount > 0) {
        statusDiv.textContent = `Live (${frameCount} FPS)`;
        frameCount = 0;
    }
}, 1000);

// Unified Frame Receiver
socket.on('frame', async (buffer) => {
    try {
        const blob = new Blob([buffer], { type: 'image/webp' });
        // Efficient Hardware Accelerated Decoding
        const bitmap = await createImageBitmap(blob);

        // Hide overlay on first frame
        if (loadingOverlay.style.display !== 'none') {
            loadingOverlay.style.opacity = 0;
            setTimeout(() => loadingOverlay.style.display = 'none', 300);
        }

        // Dynamic resize if needed
        if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
            canvas.width = bitmap.width;
            canvas.height = bitmap.height;
            viewportWidth = bitmap.width;
            viewportHeight = bitmap.height;
        }

        ctx.drawImage(bitmap, 0, 0);
        bitmap.close(); // Immediate cleanup
        frameCount++;

        // Acknowledge frame to server
        socket.emit('frame-ack');
    } catch (err) {
        console.error('Frame decode error:', err);
    }
});

// Update connection status
socket.on('connect', () => {
    statusDiv.textContent = 'Connected';
    statusDiv.style.color = '#4caf50';
});

socket.on('disconnect', () => {
    statusDiv.textContent = 'Disconnected';
    statusDiv.style.color = '#f44336';
    loadingOverlay.style.display = 'flex';
    loadingOverlay.style.opacity = 1;
});

socket.on('url-changed', (url) => {
    if (document.activeElement !== urlInput) {
        urlInput.value = url;
    }
});

// Navigation handling
urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        socket.emit('navigate', urlInput.value);
        urlInput.blur();
    }
});

backBtn.addEventListener('click', () => socket.emit('browser-control', 'back'));
forwardBtn.addEventListener('click', () => socket.emit('browser-control', 'forward'));
reloadBtn.addEventListener('click', () => socket.emit('browser-control', 'reload'));

// Interaction handling
function getCoordinates(e) {
    const rect = canvas.getBoundingClientRect();
    const scaleX = viewportWidth / rect.width;
    const scaleY = viewportHeight / rect.height;
    return {
        x: (e.clientX - rect.left) * scaleX,
        y: (e.clientY - rect.top) * scaleY
    };
}

canvas.addEventListener('mousedown', (e) => {
    const coords = getCoordinates(e);
    socket.emit('mouse-event', { type: 'mousedown', ...coords, button: e.button === 2 ? 'right' : 'left' });
});

canvas.addEventListener('mouseup', (e) => {
    const coords = getCoordinates(e);
    socket.emit('mouse-event', { type: 'mouseup', ...coords, button: e.button === 2 ? 'right' : 'left' });
});

let lastMove = 0;
canvas.addEventListener('mousemove', (e) => {
    const now = Date.now();
    if (now - lastMove < 50) return; // 20 FPS mouse updates
    lastMove = now;

    const coords = getCoordinates(e);
    socket.emit('mouse-event', { type: 'mousemove', ...coords });
});

canvas.addEventListener('click', (e) => {
    const coords = getCoordinates(e);
    socket.emit('mouse-event', { type: 'click', ...coords });
});

// Keyboard events
window.addEventListener('keydown', (e) => {
    if (document.activeElement === urlInput) return;
    socket.emit('key-event', { type: 'keydown', key: e.key });
});

window.addEventListener('keyup', (e) => {
    if (document.activeElement === urlInput) return;
    socket.emit('key-event', { type: 'keyup', key: e.key });
});

// Mouse wheel / Scroll
canvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    socket.emit('scroll', { deltaX: e.deltaX, deltaY: e.deltaY });
}, { passive: false });

canvas.addEventListener('contextmenu', (e) => e.preventDefault());
