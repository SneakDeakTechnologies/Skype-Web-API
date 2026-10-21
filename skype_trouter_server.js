import logger from './logger/logger.js';
import WebSocket from './socket/Websocket.js'
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import https from 'https';
import path from 'path';
import fs from 'fs';

dotenv.config({ 
    path: './config.env',
    quiet: true
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const options = {
    cert: fs.readFileSync(path.join(__dirname, 'crypto', 'SSL', 'trouter-cert.crt')),
    key: fs.readFileSync(path.join(__dirname, 'crypto', 'SSL', 'trouter-private.pem')),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2'
};

const trouter = https.createServer(options, (req, res) => {
    res.writeHead(400, { 'Connection': 'close' });
    res.end();
});

const wss = new WebSocketServer({
    server: trouter,
    path: '/v3/c',
    perMessageDeflate: false
});

wss.on('connection', (ws, req) => {
    const addr = req.socket.remoteAddress ?? 'unknown';
    const port = req.socket.remotePort ?? '-';

    const client = addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
    logger.info(`[INFO] Work with client: ${client}`);

    const trouter_connected = '5:1::' + JSON.stringify({
        name: 'trouter.connected',
        args: [{
            url: 'https://notify.events.sneakdeak.net/',
            reconnectUrl: 'https://transport.sneakdeak.net/',
            id: 'connect-1',
            ccid: String(req.headers['x-clientcorrelationid'] ?? '')
        }]
    });
    
    WebSocket.send(ws, client, trouter_connected);

    ws.on('message', (data, isBinary) => {
        const raw = isBinary ? data.toString('hex') : data.toString('utf8');
        if (isBinary) return;

        
        const parts = raw.split(':');

        const type = parts[0];
        const id_token = parts[1] ?? '';
        const payload = parts.length > 3? parts.slice(3).join(':'): '';

        const ack_requested = id_token.endsWith('+');
        const packetId = id_token.replace(/\+$/, '');

        let event;
        
        try {
            event = JSON.parse(payload);
        } catch {
            logger.warn(`[WARN] Invalid Socket.IO event payload: ${payload}`);
            return;
        };

        logger.info(`\n[INFO] Received event from ${client}: ${JSON.stringify(event)}`);
    });

    ws.on('close', () => {
        logger.info(`[INFO] Client ${client} disconnected\n`);
    });

    ws.on('error', (error) => {
        logger.error(`[ERROR] Client ${client} error: ${error}`);
    });
});

const skype_trouter_config = {
    host: process.env.skype_trouter_host,
    port: parseInt(process.env.skype_trouter_port)
};

trouter.listen(skype_trouter_config.port, skype_trouter_config.host, () => {
    process.title = 'Skype Trouter Server';
    logger.info(`Skype Trouter Server is running on: wss://${skype_trouter_config.host}:${skype_trouter_config.port}`);
    logger.info(`Waiting for connections...\n`);
});
