import skype_crypto from './crypto/skype_crypto.js';
import functions from './functions/functions.js';
import TCPsocket from './socket/TCPsocket.js';
import { XMLParser } from 'fast-xml-parser';
import builder from './builder/builder.js';
import logger from './logger/logger.js';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import crypto from 'crypto';
import mysql from 'mysql2';
import path from 'path';
import tls from 'tls';
import fs from 'fs';

dotenv.config({ 
    path: './config.env',
    quiet: true
});

const MySQL = mysql.createPool({
    host: process.env.mysql_host,
    user: process.env.mysql_user,
    password: process.env.mysql_password,
    database: process.env.mysql_database
});

MySQL.getConnection((error, connection) => {
    if (error) {
        throw new Error(`[MySQL] MySQL Connection Error: ${error}`);
    } else {
        logger.debug(`[MySQL] Successful MySQL Connection`);
        connection.release();
    };
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const options = {
    cert: fs.readFileSync(path.join(__dirname, 'crypto', 'SSL', 'gateway-cert.crt')),
    key: fs.readFileSync(path.join(__dirname, 'crypto', 'SSL', 'gateway-private.pem'))
};

const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseAttributeValue: true,
    parseTagValue: true,
    trimValues: true,
    allowBooleanAttributes: true,
});

const sessions = new Map();

async function handle_msnp_commands (socket, session, client, cmd, trId, type, len, payload) {
    logger.info(`[INFO] cmd=${cmd}, trId=${trId}, type=${type}, len=${len}`);
    const parsed_payload = parser.parse(payload);

    switch (cmd) {
        case "CNT":
            const connect = parsed_payload.connect;
            const nonce = crypto.randomUUID();

            session.nonce = nonce;

            const cnt_payload =
                `<connect-response>` +
                `<ver>${connect.ver}</ver>` +
                `<qostest>false</qostest>` +
                `<nonce>${nonce}</nonce>` +
                `</connect-response>`;

            const cnt = builder.build_msnp_packet(cmd, trId, type, cnt_payload);
            TCPsocket.write(client, socket, cnt);
        break;

        case "ATH":
            const user = parsed_payload.user;
            const accessToken = user["ssl-compact-ticket"].replace("t=", "");
            const uic = user.uic;

            if (!accessToken || !uic) { 
                TCPsocket.end(socket); 
                break; 
            };

            const valid_accessToken = skype_crypto.verify_access_token(accessToken);
            const valid_uic = skype_crypto.verify_uic(uic, process.env.uic_public_key);

            if (!valid_accessToken.success && !valid_accessToken.uuid || !valid_uic.success && !valid_uic.username) {
                logger.info(`[INFO] Invalid accessToken or UIC. Sending Login Fail..`);

                const ath = builder.build_login_fail(cmd, trId, "CON");
                TCPsocket.write(client, socket, ath);

                TCPsocket.end(socket);
                break;
            };

            logger.info(`[INFO] UIC and accessToken are valid. Checking for a username match..`);
            const accessToken_username = await skype_crypto.getUsernameByUUID(valid_accessToken.uuid, MySQL);

            logger.info(`\n[INFO] accessToken username: ${accessToken_username}`);
            logger.info(`[INFO] UIC username: ${valid_uic.username}`);

            if (accessToken_username !== valid_uic.username) {
                logger.info(`[INFO] Usernames don't match. Sending Login Fail..`);
                
                const ath = builder.build_login_fail(cmd, trId, "CON");
                TCPsocket.write(client, socket, ath);

                TCPsocket.end(socket);
                break;
            };

            session.authenticated = true;
            session.uuid = valid_accessToken.uuid;

            const ath = builder.build_login_ok(cmd, trId, "CON", accessToken_username);
            TCPsocket.write(client, socket, ath);
        break;

        case "BND":
            if (session.authenticated === false) {
                TCPsocket.end(socket);
                sessions.delete(socket);
            };

            const msgr = parsed_payload.msgr;

            const bnd_payload =
                `<msgr-response>` +
                `<ver>${msgr.ver}</ver>` +
                `<utctime>${Math.floor(Date.now() / 1000)}</utctime>` +
                `<nonce>${session.nonce}</nonce>` +
                `<sample-window>${0}</sample-window>` +
                `</msgr-response>`;

            const bnd = builder.build_msnp_packet(cmd, trId, "CON", bnd_payload);
            TCPsocket.write(client, socket, bnd);
        break;

        case "PUT":
            switch (type) {
                case "MSGR\\CHALLENGE":
                    const challenge = parsed_payload.challenge;

                    if (!challenge) {
                        return;
                    };

                    if (challenge.appId !== 'PROD0090YUAUV{2B') {
                        logger.warn(`[WARN] Invalid appId: ${challenge.appId}`);
                        return;
                    };

                    const calculated = builder.build_challenge_response(session.nonce);
                    const received = challenge.response?.toLowerCase();

                    logger.info(`\n[INFO] calculated=${calculated}`);
                    logger.info(`[INFO] received=${received}`);
                break;

                case "MSGR\\PRESENCE":
                    const wirePayload = payload.replace(/^\r?\n/, "");
                    const divider = wirePayload.match(/\r?\n\r?\n/);

                    if (!divider) {
                        logger.warn("[WARN] Malformed PRESENCE payload: no header separator");
                        break;
                    }

                    const headerEnd = divider.index;
                    const headers = wirePayload.slice(0, headerEnd);
                    const body = wirePayload.slice(headerEnd + divider[0].length);

                    const from = headers.match(/^From:\s*(.+)$/im)?.[1]?.trim();
                    const to = headers.match(/^To:\s*(.+)$/im)?.[1]?.trim();
                    const userXml = body.match(/<user\b[\s\S]*?<\/user>/i)?.[0];

                    if (!from || !to || !userXml) {
                        logger.warn("[WARN] PRESENCE missing From, To, or user XML");
                        break;
                    }

                    const escapeXml = value => value
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;")
                        .replace(/'/g, "&apos;");

                    const response =
                        `<presence-response>` +
                        `<from>${escapeXml(from)}</from>` +
                        `<to>${escapeXml(to)}</to>` +
                        `<notification-type>Full</notification-type>` +
                        `${userXml}` +
                        `</presence-response>`;

                    const packet = builder.build_msnp_packet(
                        "PUT", trId, type, response
                    );

                    TCPsocket.write(client, socket, packet);
            logger.info(`[INFO] Sent PRESENCE response for trid=${trId}`);
                break;
            };
        break;

        default:
            logger.warn(`[WARN] Unknown MSNP-command: ${cmd}`);
        break;
    };
};

const gateway = tls.createServer(options, (socket) => {
    const ip = socket.remoteAddress;
    const port = socket.remotePort;

    const client = `${ip}:${port}`;
    logger.info(`\n[INFO] Work with client: ${client}`);

    sessions.set(socket, {
        nonce: null,
        authenticated: false,
        uuid: null,
        status: null
    });

    socket.on('data', (data) => {
        const session = sessions.get(socket);
        const time = functions.get_time();
        logger.info(`\n[INFO] ${time} >> ${data.toString()}`);

        const text = data.toString('utf8');
        const match = text.match(/^([A-Z]+)\s+(\d+)\s+([^\r\n\s]+)\s+(\d+)\r?\n([\s\S]*)/);

        if (match) {
            const cmd = match[1];
            const trId = Number(match[2]);
            const type = match[3];
            const len = Number(match[4]);
            const payload = match[5];

            handle_msnp_commands(socket, session, client, cmd, trId, type, len, payload);
        };
    });

    socket.on('close', () => {
        const time = functions.get_time();
        sessions.delete(socket);
        logger.info(`[INFO] ${time} Client ${client} disconnected`);
    });

    socket.on('end', () => {
        const time = functions.get_time();
        sessions.delete(socket);
        logger.info(`[INFO] ${time} Client ${client} disconnected`);
    });
});

const skype_gateway_config = {
    host: process.env.skype_gateway_host,
    port: parseInt(process.env.skype_gateway_port)
};

gateway.listen(skype_gateway_config.port, skype_gateway_config.host, () => {
    process.title = 'Skype Gateway Server';
    logger.info(`Skype Gateway Server is running on: tcp://${skype_gateway_config.host}:${skype_gateway_config.port}`);
    logger.info('Waiting for connections...');
});