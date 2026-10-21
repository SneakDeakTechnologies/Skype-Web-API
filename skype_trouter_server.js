import skype_crypto from './crypto/skype_crypto.js'
import WebSocket from './socket/Websocket.js';
import logger from './logger/logger.js';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import dotenv from 'dotenv';
import https from 'https';
import http from 'http';
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

const notify_server = http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/internal/notify-invites') {
        return skype_crypto.send_json(res, 404, {
            error: 'Not found'
        });
    };

    if (!skype_crypto.secret_matches(
        req.headers['x-internal-secret'],
        process.env.trouter_internal_secret
    )) {
        return skype_crypto.send_json(res, 403, {
            error: 'Forbidden'
        });
    };

    let body = '';
    let too_large = false;

    req.setEncoding('utf8');

    req.on('data', chunk => {
        body += chunk;

        if (body.length > 4096) {
            too_large = true;
        };
    });

    req.on('end', () => {
        if (too_large) {
            return skype_crypto.send_json(res, 413, {
                error: 'Payload too large'
            });
        };

        let data;

        try {
            data = JSON.parse(body);
        } catch {
            return skype_crypto.send_json(res, 400, {
                error: 'Invalid JSON'
            });
        };

        const recipient_uuid = data?.recipient_uuid;

        if (
            typeof recipient_uuid !== 'string' ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
                .test(recipient_uuid)
        ) {
            return skype_crypto.send_json(res, 400, {
                error: 'Invalid recipient_uuid'
            });
        };

        const delivered = notify_invite(recipient_uuid);

        return skype_crypto.send_json(res, 200, {
            ok: true,
            delivered
        });
    });
});

notify_server.listen(Number(process.env.trouter_notify_port), '127.0.0.1');

const wss = new WebSocketServer({
    server: trouter,
    path: '/v3/c',
    perMessageDeflate: false
});

const sockets_to_uuid = new Map();
const uuid_to_socket = new WeakMap();
const client_by_socket = new WeakMap();

let next_notifyId = 20000;

function register_socket(uuid, ws, client) {
    const user_uuid = uuid.toLowerCase();

    if (!sockets_to_uuid.has(user_uuid)) {
        sockets_to_uuid.set(user_uuid, new Set());
    };

    sockets_to_uuid.get(user_uuid).add(ws);
    uuid_to_socket.set(ws, user_uuid);
    client_by_socket.set(ws, client);
};

function unregister_socket(ws) {
    const user_uuid = uuid_to_socket.get(ws);
    if (!user_uuid) return;

    const sockets = sockets_to_uuid.get(user_uuid);

    if (sockets) {
        sockets.delete(ws);

        if (sockets.size === 0) {
            sockets_to_uuid.delete(user_uuid);
        };
    };

    uuid_to_socket.delete(ws);
    client_by_socket.delete(ws);
};

function notify_invite(recipient_uuid) {
    const user_uuid = recipient_uuid.toLowerCase();
    const sockets = sockets_to_uuid.get(user_uuid);

    if (!sockets || sockets.size === 0) {
        logger.info(`[Trouter] User ${user_uuid} is offline`);
        return 0;
    };

    let sent = 0;

    for (const ws of [...sockets]) {
        if (ws.readyState !== 1) {
            unregister_socket(ws);
            continue;
        };

        const request = {
            id: ++next_notifyId,
            method: 'POST',
            url: '/notification/v1/events/803',
            headers: {
                'Content-Type': 'application/json'
            },
            body: '{}'
        };

        const packet = '3:::' + JSON.stringify(request);
        const client = client_by_socket.get(ws) ?? 'unknown';

        WebSocket.send(ws, client, packet);
        sent++;

        logger.info(
            `[Trouter] Invite notification sent to ${user_uuid}`
        );
    };

    return sent;
};

wss.on('connection', (ws, req) => {
    const addr = req.socket.remoteAddress ?? 'unknown';
    const port = req.socket.remotePort ?? '-';

    const client = addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
    logger.info(`[INFO] Work with client: ${client}`);

    const skypetoken = req.headers['x-skypetoken'];

    if (!skypetoken) {
        logger.warn(`[WARN] Missing Skypetoken from ${client}`);
        ws.close(1008, 'Missing authentication token');
        return;
    };

    const verify = skype_crypto.verify_skypetoken(skypetoken);

    if (!verify?.success || !verify.uuid) {
        logger.warn(`[WARN] Invalid Skype token from ${client}`);
        ws.close(1008, 'Unauthorized');
        return;
    };

    const user_uuid = verify.uuid.toLowerCase();
    register_socket(user_uuid, ws, client);

    logger.info(`[INFO] User ${user_uuid} authenticated and registered in Trouter\n`);

    const trouter_connected = '5:1::' + JSON.stringify({
        name: 'trouter.connected',
        args: [{
            url: 'https://notify.events.sneakdeak.net/',
            reconnectUrl: 'https://reconnect.sneakdeak.net/',
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

    ws.on('close', (code, reason) => {
        unregister_socket(ws);

        logger.info(`[INFO] Client ${client} disconnected: ${code} ${reason.toString()}`);
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
