// node-gui/server.js
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Be more restrictive in production
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const BLOCKED_IPS_FILE = path.join(__dirname, '../python-sniffer/blocked_ips.json');
const ALERT_LOGS_FILE = path.join(__dirname, '../python-sniffer/alert_logs.json');

// Keep track of blocked IPs
let blockedIPs = new Set();

// Load previously blocked IPs if file exists
try {
    if (fs.existsSync(BLOCKED_IPS_FILE)) {
        const data = JSON.parse(fs.readFileSync(BLOCKED_IPS_FILE));
        if (data.blocked_ips && Array.isArray(data.blocked_ips)) {
            data.blocked_ips.forEach(ip => blockedIPs.add(ip));
            console.log(`Loaded ${blockedIPs.size} previously blocked IPs`);
        }
    }
} catch (err) {
    console.error('Error loading blocked IPs file:', err);
}

// Load alert logs if file exists
let alertLogs = [];
try {
    if (fs.existsSync(ALERT_LOGS_FILE)) {
        alertLogs = JSON.parse(fs.readFileSync(ALERT_LOGS_FILE));
        console.log(`Loaded ${alertLogs.length} previous alerts`);
    }
} catch (err) {
    console.error('Error loading alert logs file:', err);
}

// Save blocked IPs to file
function saveBlockedIPs() {
    try {
        fs.writeFileSync(
            BLOCKED_IPS_FILE, 
            JSON.stringify({ blocked_ips: Array.from(blockedIPs) })
        );
    } catch (err) {
        console.error('Error saving blocked IPs file:', err);
    }
}

// Save alert logs to file
function saveAlertLogs() {
    try {
        fs.writeFileSync(
            ALERT_LOGS_FILE,
            JSON.stringify(alertLogs, null, 2)
        );
    } catch (err) {
        console.error('Error saving alert logs:', err);
    }
}

// Serve the static HTML file for the GUI
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static files (like CSS, client-side JS)
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint to get all blocked IPs
app.get('/api/blocked-ips', (req, res) => {
    res.json({ blocked_ips: Array.from(blockedIPs) });
});

// API endpoint to get alert logs
app.get('/api/alert-logs', (req, res) => {
    res.json({ alerts: alertLogs });
});

// Keep track of connected browser clients
let browserClients = 0;
let pythonClients = 0;

io.on('connection', (socket) => {
    console.log('A client connected:', socket.id);

    const userAgent = socket.handshake.headers['user-agent'] || '';
    const isPythonClient = userAgent.toLowerCase().includes('python-socketio');

    if (!isPythonClient) {
        browserClients++;
        console.log(`Browser client connected. Total browsers: ${browserClients}`);
        
        // Send current blocked IPs to the new browser client
        socket.emit('init_blocked_ips', { ips: Array.from(blockedIPs) });
        
        // Send initial alert logs
        socket.emit('init_alert_logs', { alerts: alertLogs });
    } else {
        pythonClients++;
        console.log(`Python sniffer client connected: ${socket.id}`);
    }

    // When a suspicious packet is detected by the Python script
    socket.on('suspicious_packet', (data) => {
        console.log('Received suspicious packet data:', data);
        // Add to alert logs
        alertLogs.push(data);
        if (alertLogs.length > 1000) {
            alertLogs = alertLogs.slice(-1000); // Keep only last 1000 alerts
        }
        saveAlertLogs();
        
        // Broadcast to all browser clients
        io.emit('display_packet', data);
    });

    // When an IP is blocked by the Python sniffer
    socket.on('ip_blocked', (data) => {
        console.log('IP blocked:', data.ip);
        if (data.ip) {
            blockedIPs.add(data.ip);
            saveBlockedIPs();
            io.emit('ip_blocked', data); // Forward to browsers to update their UI
        }
    });

    // When an IP is unblocked
    socket.on('ip_unblocked', (data) => {
        console.log('IP unblocked:', data.ip);
        if (data.ip && blockedIPs.has(data.ip)) {
            blockedIPs.delete(data.ip);
            saveBlockedIPs();
            io.emit('ip_unblocked', data); // Forward to browsers to update their UI
        }
    });
    
    // When an IP is manually blocked from the web UI
    socket.on('block_ip', (data) => {
        console.log('Request to block IP:', data.ip);
        if (data.ip) {
            blockedIPs.add(data.ip);
            saveBlockedIPs();
            // Broadcast this event to the Python sniffer
            io.emit('block_ip', data);
            // Also broadcast to all browsers
            io.emit('ip_blocked', data);
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
        if (!isPythonClient) {
            browserClients--;
            console.log(`Browser client disconnected. Total browsers: ${browserClients}`);
        } else {
            pythonClients--;
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

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down server...');
    saveBlockedIPs();
    saveAlertLogs();
    process.exit(0);
});