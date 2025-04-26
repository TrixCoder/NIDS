// node-gui/server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Be more restrictive in production
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;

// Serve the static HTML file for the GUI
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static files (like CSS, client-side JS)
app.use(express.static(path.join(__dirname, 'public')));

// Keep track of connected browser clients
let browserClients = 0;

io.on('connection', (socket) => {
    console.log('A client connected:', socket.id);

    const userAgent = socket.handshake.headers['user-agent'] || '';
    const isPythonClient = userAgent.toLowerCase().includes('python-socketio');

    if (!isPythonClient) {
        browserClients++;
        console.log(`Browser client connected. Total browsers: ${browserClients}`);
    } else {
        console.log(`Python sniffer client connected: ${socket.id}`);
    }

    // When a suspicious packet is detected by the Python script
    socket.on('suspicious_packet', (data) => {
        console.log('Received suspicious packet data:', data);
        // Broadcast to all browser clients
        io.emit('display_packet', data);
    });

    // When an IP is blocked by the Python sniffer
    socket.on('ip_blocked', (data) => {
        console.log('IP blocked:', data.ip);
        io.emit('ip_blocked', data); // Forward to browsers to update their UI
    });

    // When an IP is unblocked by the browser GUI
    socket.on('unblock_ip', (data) => {
        console.log('Request to unblock IP:', data.ip);
        // Broadcast this event to the Python sniffer
        io.emit('unblock_ip', data);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        if (!isPythonClient) {
            browserClients--;
            console.log(`Browser client disconnected. Total browsers: ${browserClients}`);
        } else {
            console.log(`Python sniffer client disconnected: ${socket.id}`);
        }
    });

    socket.on('error', (err) => {
        console.error('Socket error:', err);
    });
});

// Start the server
server.listen(PORT, () => {
    console.log(`Node.js GUI server listening on *:${PORT}`);
});
