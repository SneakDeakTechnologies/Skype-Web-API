import skype_crypto from './crypto/skype_crypto.js';
import rate_limit from 'express-rate-limit';
import logger from './logger/logger.js';
import { fileURLToPath } from 'url';
import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import mysql from 'mysql2';
import https from 'https';
import cors from 'cors';
import path from 'path';
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
        logger.info(`\n[MySQL] Successful MySQL Connection`);
        connection.release();
    };
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const options = {
    cert: fs.readFileSync(path.join(__dirname, 'crypto', 'SSL', 'cert.crt')),
    key: fs.readFileSync(path.join(__dirname, 'crypto', 'SSL', 'private.pem'))
};

const api = express();
const https_server = https.createServer(options, api);

api.use((req, res, next) => {
    logger.info(`\nURL: ${req.url}`);
    logger.info(`Method: ${req.method}`);
    logger.info(`From: ${req.ip}`);
    next();
});

api.use(cors());
api.use((req, res, next) => {
    if (
        req.method === 'POST' &&
        (
            req.path === '/contacts/v2/users/self/contacts' ||
            req.path === '/users/batch/profiles'
        ) &&
        !req.headers['content-type']
    ) {
        req.headers['content-type'] = 'application/json';
    }

    next();
});
api.use(express.json());
api.use(express.urlencoded({ extended: true }));
api.use(express.raw({ 
    type: ['image/png', 'image/jpeg', 'image/jpg', 'application/octet-stream'], 
    limit: '10mb' 
}));
api.use(express.static(path.join(__dirname, 'public')));

async function notify_trouter_invite(recepient_uuid) {
    const secret = process.env.trouter_internal_secret;
    const url = process.env.trouter_notify_url || 'http://127.0.0.1:8765/internal/notify-invites';

    if (!secret) {
        logger.error('[API] Trouter internal secret is not configured');
        return;
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Internal-Secret': secret
            },
            body: JSON.stringify({ recepient_uuid }),
            signal: AbortSignal.timeout(2000)
        });

        if (!response.ok) {
            logger.warn(
                `[INFO] Trouter notification failed: HTTP ${response.status}`
            );
            return;
        }

        const result = await response.json();

        logger.info(
            `[INFO] Trouter notification result: ${JSON.stringify(result)}`
        );
    } catch (error) {
        logger.warn(`[INFO] Trouter notification error: ${error.message}`);
    };
};

api.get('/config/v1/Skype/:skypeVer', (req, res) => {
    const { skypeVer } = req.params;

    const expires = new Date(Date.now() + 47 * 60 * 60 * 1000).toUTCString();
    res.set('Expires', expires);

    return res.status(200).json({
        version: 1,
        ui_version: skypeVer,

        WIN: {
            Features: {
                NativeOAuthLogin: {
                    Enabled: true
                },
                NativeHome: {
                    Enabled: true
                },
                ClientThemes: {
                    Enabled: true,
                    EnabledOnLogin: true
                },
                ThemedMenus: {
                    Enabled: true
                }
            }
        },

        Identity: {
            Login: {
                RequireDsn: false
            }
        }
    });
});

api.get('/oauth20_authorize.srf', (req, res) => {
    var { client_id, locale, redirect_uri, signup, username } = req.query;

    if (!client_id) return res.status(400).end();
    if (!locale) locale = "en";
    if (!redirect_uri) return res.status(400).end();
    
    MySQL.query(
        'SELECT * FROM live_apps WHERE clientId = ?',
        [client_id],
        async (error, apps) => {
            if (error) return res.status(500).end();
            if (!apps || apps.length === 0) return res.status(401).end();

            const app = apps[0];
            const name = app.name;
            
            if (signup === "1") {
                const register = `
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta http-equiv="X-UA-Compatible" content="IE=11">
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Skype</title>
                    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet">
                    <script src="../locale/${locale}.js" charset="utf-8"></script>
                    <link rel="stylesheet" href="../css/register.css">
                    <script>
                        window.ServerData = {
                            redirect_uri: ${JSON.stringify(redirect_uri)},
                            urlPost: ${JSON.stringify("/ppsecure/post.srf")}
                        };
                    </script>
                </head>
                <body>
                    <div class="registerForm" id="registerForm">
                        <img class="msa_skype_logo" src="../img/msa_skype_logo.png">
                        <div class="error" id="error">
                            <img class="error_img" src="../img/error.png">
                            <p class="error_text" id="error_text"></p>
                        </div>
                        <h1 class="register_account" id="register_account"></h1>
                        <input class="input_skypename" type="text" id="username" placeholder="">
                        <input class="input_passwd" type="password" id="passwd" placeholder="">
                        <input class="input_confirm_passwd" type="password" id="confirm_passwd" placeholder="">
                        <button class="back" id="back_btn"></button>
                        <button class="register" id="register_btn"></button>
                    </div>
                    <script src="../js/register.js"></script>
                </body>
                </html>`;
                return res.status(200).send(register);
            };

            const login = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta http-equiv="X-UA-Compatible" content="IE=11">
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${name}</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap" rel="stylesheet">
                <script src="../locale/${locale}.js" charset="utf-8"></script>
                <link rel="stylesheet" href="../css/login.css">
                <script>
                    window.ServerData = {
                        username: ${JSON.stringify(username)},
                        redirect_uri: ${JSON.stringify(redirect_uri)},
                        urlPost: ${JSON.stringify("/ppsecure/post.srf")}
                    };
                </script>
                <script src="../js/login.js"></script>
            </head>
            <body>
            <div class="passwordForm" id="passwordForm">
                <img class="msa_skype_logo" src="../img/msa_skype_logo.png">
                <div class="error" id="error">
                    <img class="error_img" src="../img/error.png">
                    <p class="error_text" id="error_text"></p>
                </div>
                <h1 class="enter_passwd" id="enter_passwd"></h1>
                <p class="enter_signin" id="enter_signin"></p>
                <input class="input_passwd" type="password" id="passwd" placeholder="">
                <button class="back" id="back_btn"></button>
                <button class="signin" id="signin_btn"></button>
                <h1 class="forgot_link" id="forgot_link"><a></a></h1>
            </div>
            </body>
            </html>`;
            return res.status(200).send(login);
        }
    );
});

api.post('/ppsecure/post.srf', (req, res) => {
    const { redirect_uri } = req.query; 
    const { username, passwd, type } = req.body;

    if (!username || !passwd || !type) return res.status(400).end();

    if (type === "login") {
        MySQL.query(
            'SELECT username, password, BIN_TO_UUID(uuid, 1) AS uuid FROM skype_users WHERE username = ?',
            [username],
            (error, users) => {
                if (error) return res.status(500).end();
                if (!users || users.length === 0) return res.status(401).end();

                const user = users[0];
                const valid_passwd = user.password;

                const hash_passwd = `${username}\nskyper\n${passwd}`;
                const hashed_passwd = crypto.createHash("md5").update(hash_passwd).digest('hex');

                if (hashed_passwd === valid_passwd) {
                    const access_token = skype_crypto.generate_access_token(user.uuid, { iss: "sda", aud: "skype", type: "access", token_ttl: 86400 });
                    const refresh_token = skype_crypto.generate_refresh_token()

                    MySQL.query(
                        'UPDATE skype_users SET refresh_token = ? WHERE uuid = UUID_TO_BIN(?, 1)',
                        [refresh_token, user.uuid],
                        (error) => {
                            if (error) return res.status(500).end();

                            return res.status(200).json({
                                url: redirect_uri +
                                    `#access_token=${access_token}` +
                                    `&refresh_token=${refresh_token}` +
                                    `&token_type=bearer`
                            });
                        }
                    )
                } else {
                    return res.status(401).end();
                };
            }
        );
    } else if (type === "registration") {
        MySQL.query(
            'SELECT username, password, BIN_TO_UUID(uuid, 1) AS uuid FROM skype_users WHERE username = ?',
            [username],
            (error, users) => {
                if (error) return res.status(500).end();
                if (users && users.length > 0) return res.status(409).end();

                const hash_passwd = `${username}\nskyper\n${passwd}`;
                const hashed_passwd = crypto.createHash("md5").update(hash_passwd).digest('hex');
                const uuid = crypto.randomUUID();

                const refresh_token = skype_crypto.generate_refresh_token();
                const access_token = skype_crypto.generate_access_token(uuid, { iss: "sda", aud: "skype", type: "access", token_ttl: 86400 });

                MySQL.query(
                    'INSERT INTO skype_users(username, uuid, password, refresh_token) VALUES (?, UUID_TO_BIN(?, 1), ?, ?)',
                    [username, uuid, hashed_passwd, refresh_token],
                    (error) => {
                        if (error) return res.status(500).end();
                        if (username === "echo123") {
                            return res.status(200).json({
                                url: redirect_uri +
                                    `#access_token=${access_token}` +
                                    `&refresh_token=${refresh_token}` +
                                    `&token_type=bearer`
                            });
                        };
                            
                        MySQL.query(
                        `SELECT BIN_TO_UUID(uuid, 1) AS uuid
                        FROM skype_users
                        WHERE username = ? AND uuid IS NOT NULL
                        LIMIT 1`,
                        ['echo123'],
                        (error, users) => {
                            if (error) return res.status(500).end();
                            if (!users || users.length === 0) return res.status(500).end();

                            const echo = users[0];
                            const display_name = skype_crypto.get_fullname(echo);

                            MySQL.query(
                                `INSERT INTO skype_contacts
                                    (owner_uuid, contact_uuid, relation_type,
                                    authorized, blocked, display_name)
                                VALUES
                                    (UUID_TO_BIN(?, 1), UUID_TO_BIN(?, 1),
                                    'contact', TRUE, FALSE, ?)`,
                                [uuid, users[0].uuid, display_name],
                                (error) => {
                                    if (error) {
                                        logger.error(
                                            `[Registration] Failed to add echo123: ${error.message}`
                                        );
                                        return res.status(500).end();
                                    }

                                    return res.status(200).json({
                                        url: redirect_uri +
                                            `#access_token=${access_token}` +
                                            `&refresh_token=${refresh_token}` +
                                            `&token_type=bearer`
                                    });
                                }
                            );
                        }
                    );
                    }
                );
            }
        ); 
    };
});

api.get('/oauth20_desktop.srf', (req, res) => {
    return res.status(200).end();
});

api.post('/oauth20_token.srf', (req, res) => {
    const { grant_type, scope } = req.body;
    const type = req.body[grant_type];

    MySQL.query(
        'SELECT refresh_token, BIN_TO_UUID(uuid, 1) AS uuid FROM skype_users WHERE refresh_token = ?',
        [type],
        (error, users) => {
            if (error) return res.status(500).end();
            if (!users || users.length === 0) return res.status(401).end();

            const user = users[0];
            const refresh_token = user.refresh_token;
            const uuid = user.uuid;

            const access_token = skype_crypto.generate_access_token(user.uuid, { iss: "sda", aud: "skype", type: "access", token_ttl: 86400 });
            return res.status(200).json({
                token_type: "bearer",
                expires_in: 86400,
                scope: scope,
                access_token: access_token,
                refresh_token: refresh_token,
                user_id: user.uuid
            });
        }
    );
});

api.post('/rps/skypetoken', (req, res) => {
    const { access_token } = req.body;
    if (!access_token) return res.status(400).end();

    const verify = skype_crypto.verify_access_token(access_token);
    if (!verify?.success) return res.status(401).end();

    try {
        MySQL.query(
            'SELECT * FROM skype_users WHERE uuid = UUID_TO_BIN(?, 1)',
            [verify.uuid],
            (error, users) => {
                if (error) return res.status(500).end();
                if (!users || users.length === 0) return res.status(401).end();

                const user = users[0];
                const username = user.username;

                const skypetoken = skype_crypto.generate_skypetoken(verify.uuid, username, 86400);
                return res.status(200).json({
                    skypetoken: skypetoken,
                    expiresIn: 86400
                });
            }
        );
    } catch (error) {
        return res.status(500).end();
    };
});

api.get('/kd', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    const sessionKey = crypto.randomBytes(16).toString("base64url");
    const ticket = crypto.randomBytes(16).toString("base64url");

    return res.status(200).json({
        sessionKey: sessionKey,
        ticket: ticket
    });
});

api.get('/tokens', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    return res.status(200).json({
        expires: 3600,
        tokens: [
            {
                realm: "relay.sneakdeak.net",
                username: "test123",
                password: "123"
            }
        ]
    });
});

api.get('/users/self/profile', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    MySQL.query(
        'SELECT * FROM skype_users WHERE uuid = UUID_TO_BIN(?, 1) LIMIT 1',
        [verify.uuid],
        (error, users) => {
            if (error) {
                logger.error(`[Profile] Failed to get self profile: ${error.message || error}`);
                return res.status(500).end();
            }
            if (!users?.length) return res.status(404).end();

            const user = users[0];
            const fullname = skype_crypto.get_fullname(user) || user.username || verify.skypename || '';
            return res.status(200).json({
                username: user.username || verify.skypename || '',
                fullname,
                firstname: user.first_name ?? '',
                lastname: user.last_name ?? '',
                mood: user.mood ?? '',
                richMood: user.richMood ?? '',
                avatarUrl: `https://api.skype.com/users/${user.username}/profile/avatar`,
                phoneMobile: user.phoneMobile ?? '',
                phoneHome: user.phoneHome ?? '',
                phoneOffice: user.phoneOffice ?? '',
                emails: skype_crypto.normalize_emails(user.emails),
                country: user.country ?? '',
                province: user.province ?? '',
                city: user.city ?? '',
                homepage: user.homepage ?? '',
                jobtitle: user.jobtitle ?? '',
                gender: user.gender ?? null,
                birthday: user.birthday ?? null,
                language: user.language ?? '',
                about: user.about ?? ''
            });
        }
    );
});

api.post('/users/batch/profiles', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    const raw_usernames = req.body?.usernames;
    if (!Array.isArray(raw_usernames)) return res.status(400).end();
    if (raw_usernames.length > 500) return res.status(413).end();

    const usernames = [...new Set(raw_usernames.map(skype_crypto.normalize_profile_username).filter(Boolean))];
    if (usernames.length === 0) return res.status(200).json([]);

    const placeholders = usernames.map(() => '?').join(', ');
    MySQL.query(
        `SELECT * FROM skype_users WHERE username IN (${placeholders})`,
        usernames,
        (error, rows) => {
            if (error) return res.status(500).end();

            const profiles_by_username = new Map();
            for (const user of rows || []) {
                const username = String(user.username || '');
                if (!username) continue;

                const fullname = skype_crypto.get_fullname(user) || username;
                profiles_by_username.set(username.toLowerCase(), {
                    username,
                    fullname,
                    firstname: user.first_name ?? '',
                    lastname: user.last_name ?? '',
                    birthday: user.birthday ?? null,
                    gender: user.gender ?? null,
                    avatarUrl: `https://api.skype.com/users/${user.username}/profile/avatar`,
                    language: user.language ?? '',
                    country: user.country ?? '',
                    province: user.province ?? '',
                    city: user.city ?? '',
                    homepage: user.homepage ?? '',
                    jobtitle: user.jobtitle ?? '',
                    about: user.about ?? '',
                    phoneHome: user.phoneHome ?? '',
                    phoneOffice: user.phoneOffice ?? '',
                    phoneMobile: user.phoneMobile ?? '',
                    emails: skype_crypto.normalize_emails(user.emails),
                    mood: user.mood ?? '',
                    richMood: user.richMood ?? ''
                });
            };

            const profiles = usernames
                .map(username => profiles_by_username.get(username.toLowerCase()))
                .filter(Boolean);
            return res.status(200).json(profiles);
        }
    );
});

api.post('/users/self/profile/partial', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    const payload = req.body?.payload ?? req.body;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return res.status(400).end();
    };

    MySQL.query(
        'SELECT username, first_name, last_name FROM skype_users WHERE uuid = UUID_TO_BIN(?, 1) LIMIT 1',
        [verify.uuid],
        (error, users) => {
            if (error) return res.status(500).end();
            if (!users?.length) return res.status(404).end();

            const current = users[0];
            const updates = new Map();
            const has_fullname = skype_crypto.hasOwn(payload, 'fullname') || skype_crypto.hasOwn(payload, 'fullName') || typeof payload.name === 'string';
            const fullname_key = skype_crypto.hasOwn(payload, 'fullname') ? 'fullname'
                : skype_crypto.hasOwn(payload, 'fullName') ? 'fullName' : 'name';
            let firstName = current.first_name ?? '';
            let lastName = current.last_name ?? '';
            let names_changed = false;

            if (has_fullname) {
                const value = payload[fullname_key];
                if (value !== null && typeof value !== 'string') return res.status(400).end();
                const normalized = skype_crypto.normalize_fullname(value ?? '');
                const split = skype_crypto.split_fullname(normalized);
                firstName = split.first_name;
                lastName = split.last_name;
                names_changed = true;
            } else {
                const nested_name = payload.name && typeof payload.name === 'object' && !Array.isArray(payload.name)
                    ? payload.name : null;
                const first_key = skype_crypto.hasOwn(payload, 'firstname') ? 'firstname'
                    : skype_crypto.hasOwn(payload, 'first_name') ? 'first_name'
                    : nested_name && skype_crypto.hasOwn(nested_name, 'first') ? 'name.first' : null;
                const last_key = skype_crypto.hasOwn(payload, 'lastname') ? 'lastname'
                    : skype_crypto.hasOwn(payload, 'last_name') ? 'last_name'
                    : nested_name && skype_crypto.hasOwn(nested_name, 'surname') ? 'name.surname'
                    : nested_name && skype_crypto.hasOwn(nested_name, 'last') ? 'name.last' : null;

                if (first_key) {
                    const value = first_key === 'name.first' ? nested_name.first : payload[first_key];
                    if (value !== null && typeof value !== 'string') return res.status(400).end();
                    firstName = skype_crypto.normalize_fullname(value ?? '');
                    names_changed = true;
                };

                if (last_key) {
                    const value = last_key === 'name.surname' ? nested_name.surname
                        : last_key === 'name.last' ? nested_name.last : payload[last_key];
                    if (value !== null && typeof value !== 'string') return res.status(400).end();
                    lastName = skype_crypto.normalize_fullname(value ?? '');
                    names_changed = true;
                };
            };

            if (names_changed) {
                updates.set('first_name', firstName);
                updates.set('last_name', lastName);
            }''
            
            const profileFields = [
                { column: 'mood', keys: ['mood'] },
                { column: 'richMood', keys: ['richMood', 'rich_mood', 'richMoodText', 'rich_mood_text'] },
                { column: 'country', keys: ['country'] },
                { column: 'province', keys: ['province', 'state'] },
                { column: 'city', keys: ['city'] },
                { column: 'homepage', keys: ['homepage', 'website'] },
                { column: 'jobtitle', keys: ['jobtitle', 'jobTitle', 'title'] },
                { column: 'about', keys: ['about'] },
                { column: 'birthday', keys: ['birthday'] },
                { column: 'language', keys: ['language'] },
                { column: 'phoneMobile', keys: ['phoneMobile'] },
                { column: 'phoneHome', keys: ['phoneHome'] },
                { column: 'phoneOffice', keys: ['phoneOffice'] }
            ];

            for (const field of profileFields) {
                const key = field.keys.find(candidate => skype_crypto.hasOwn(payload, candidate));
                if (!key) continue;

                const value = payload[key];
                if (value !== null && typeof value !== 'string') return res.status(400).end();
                const normalized = value === null ? null : value.trim();
                if (field.column === 'birthday' && normalized !== null && normalized !== '' && !/^\d{4}-\d{2}-\d{2}$/.test(normalized)) {
                    return res.status(400).end();
                }
                updates.set(field.column, normalized === '' && field.column === 'birthday' ? null : normalized);
            };

            if (skype_crypto.hasOwn(payload, 'gender')) {
                const value = payload.gender;
                if (value === null || value === '') {
                    updates.set('gender', null);
                } else if (Number.isInteger(value)) {
                    updates.set('gender', value);
                } else if (typeof value === 'string' && /^-?\d+$/.test(value.trim())) {
                    updates.set('gender', Number(value.trim()));
                } else if (typeof value === 'string' && ['male', 'female'].includes(value.trim().toLowerCase())) {
                    updates.set('gender', value.trim().toLowerCase() === 'male' ? 1 : 2);
                } else {
                    return res.status(400).end();
                };
            };

            if (skype_crypto.hasOwn(payload, 'emails')) {
                if (payload.emails !== null && !Array.isArray(payload.emails)) return res.status(400).end();
                updates.set('emails', JSON.stringify(Array.isArray(payload.emails) ? payload.emails : []));
            };

            if (Array.isArray(payload.phones)) {
                const phoneColumns = { home: 'phoneHome', mobile: 'phoneMobile', office: 'phoneOffice' };
                for (const phone of payload.phones) {
                    if (!phone || typeof phone !== 'object' || Array.isArray(phone)) continue;
                    const column = phoneColumns[String(phone.type || '').toLowerCase()];
                    if (!column || !skype_crypto.hasOwn(phone, 'number')) continue;
                    if (phone.number !== null && typeof phone.number !== 'string') return res.status(400).end();
                    updates.set(column, phone.number === null ? null : phone.number.trim());
                }
            }

            if (Array.isArray(payload.locations) && payload.locations.length > 0) {
                const location = payload.locations.find(item => item && item.type === 'home') || payload.locations[0];
                if (location && typeof location === 'object') {
                    const locationFields = [
                        ['country', location.country],
                        ['province', location.state ?? location.province],
                        ['city', location.city]
                    ];
                    for (const [column, value] of locationFields) {
                        if (value === undefined) continue;
                        if (value !== null && typeof value !== 'string') return res.status(400).end();
                        updates.set(column, value === null ? null : value.trim());
                    };
                };
            };

            if (updates.size === 0) return res.status(400).end();

            const columns = [...updates.keys()];
            const values = [...updates.values()];
            const sql = `UPDATE skype_users SET ${columns.map(column => `\`${column}\` = ?`).join(', ')} WHERE uuid = UUID_TO_BIN(?, 1)`;

            MySQL.query(sql, [...values, verify.uuid], update_error => {
                if (update_error) {
                    return res.status(500).end();
                };
                return res.status(200).end();
            });
        }
    );
});

api.get('/v1/avatars/:username', async (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    const { username } = req.params;
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify.success) return res.status(401).end();

    try {
        const uuid = await skype_crypto.getUUIDByUsername(username, MySQL);
        if (!uuid) return res.status(404).end();

        const avatar_path = skype_crypto.getAvatarByUUID(uuid);
        if (!avatar_path) return res.status(404).end();

        return res.sendFile(avatar_path);
    } catch (error) {
        return res.status(500).end();
    };
});

api.get('/users/:username/profile/avatar', async (req, res) => {
    const { username } = req.params;

    try {
        const uuid = await skype_crypto.getUUIDByUsername(username, MySQL);
        if (!uuid) return res.status(404).end();

        const avatar_path = skype_crypto.getAvatarByUUID(uuid);
        if (!avatar_path) return res.status(404).end();

        return res.sendFile(avatar_path);
    } catch (error) {
        return res.status(500).end();
    };
});

api.put('/v1/avatars/:username', async (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    const { username } = req.params;

    if (!skypetoken) return res.status(400).end();
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).end();
    };

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify.success) return res.status(401).end();

    if (verify.skypename && verify.skypename !== username) {
        return res.status(403).end();
    };

    try {
        const uuid = await skype_crypto.getUUIDByUsername(username, MySQL);
        if (!uuid) return res.status(404).end();

        const avatar = await skype_crypto.setAvatarByUUID(uuid, req.body);
        
        if (!avatar.success) {
            return res.status(415).end();
        };

        return res.status(200).end();
    } catch (error) {
        return res.status(500).end();
    };
});

api.get('/contacts/v2/users/self', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    const req_size = Number(req.query.page_size);
    const page_size = Number.isInteger(req_size) && req_size > 0 ? Math.min(req_size, 100) : 100;

    MySQL.query(
        `SELECT * FROM skype_contacts AS c JOIN skype_users AS u ON u.uuid = c.contact_uuid
         WHERE c.owner_uuid = UUID_TO_BIN(?, 1)
           AND c.relation_type = 'contact'
         ORDER BY c.is_favorite DESC, u.username ASC
         LIMIT ?`,
        [verify.uuid, page_size],
        (error, contacts_users) => {
            if (error) {
                return res.status(500).end();
            };

            const contacts = contacts_users.map(user => ({
                mri: `8:${user.username}`,
                display_name:
                    user.display_name ||
                    [
                        user.first_name,
                        user.last_name
                    ].filter(Boolean).join(' ') ||
                    user.username,
                authorized: Boolean(user.authorized),
                blocked: Boolean(user.blocked),
                profile: {
                    name: {
                        first: user.first_name ?? '',
                        surname: user.last_name ?? ''
                    },
                    mood: user.mood ?? '',
                    richMood: user.richMood ?? '',
                    avatar_url: `https://api.skype.com/users/${user.username}/profile/avatar`,
                    birthday: user.birthday ?? null,
                    gender: skype_crypto.get_gender(user.gender),
                    language: user.language ?? '',
                    locations: [{
                        type: "home",
                        country: user.country ?? '',
                        city: user.city ?? '',
                        state: user.province ?? ''
                    }],
                    about: user.about ?? '',
                    website: user.homepage ?? '',
                    jobtitle: user.jobtitle ?? '',
                    phones: [
                        user.phoneHome ? { number: user.phoneHome, type: 'home' } : null,
                        user.phoneMobile ? { number: user.phoneMobile, type: 'mobile' } : null,
                        user.phoneOffice ? { number: user.phoneOffice, type: 'office' } : null
                    ].filter(Boolean),
                    emails: skype_crypto.normalize_emails(user.emails)
                }
            }));

            const blocklist = contacts_users
                .filter(user => user.blocked)
                .map(user => ({
                    mri: `8:${user.username}`
                }));

            return res.status(200).json({
                contacts,
                blocklist,
                groups: []
            });
        }
    );
});

api.get('/contacts/v2/users/self/invites', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    MySQL.query(
        `SELECT u.username, u.first_name, u.last_name, c.greeting, c.created_at FROM skype_contacts AS c JOIN skype_users AS u ON u.uuid = c.owner_uuid WHERE c.contact_uuid = UUID_TO_BIN(?, 1) AND c.relation_type = 'invite' ORDER BY c.created_at ASC LIMIT 100`,
        [verify.uuid],
        (error, rows) => {
            if (error) return res.status(500).end();

            const invite_list = rows.map(invite => ({
                mri: `8:${invite.username}`,
                displayname: skype_crypto.get_fullname(invite) || invite.username,
                greeting: invite.greeting || '',
                invites: [{
                    time: new Date(invite.created_at)
                        .toISOString()
                        .replace(/\.\d{3}Z$/, 'Z')
                }]
            }));

            return res.status(200).json({ invite_list });
        }
    );
});

api.post('/contacts/v2/users/self/contacts', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    const { mri, send_invite, greeting } = req.body;

    if (typeof mri !== 'string' || mri.length > 256 || !/^(?:8|16):/.test(mri.trim())) {
        return res.status(400).end();
    };

    if (typeof send_invite !== 'boolean') {
        return res.status(400).end();
    };

    if (typeof greeting !== 'string' || !greeting.trim()) {
        return res.status(400).end();
    };

    const identity = mri.trim();
    const contact_username = identity.slice(identity.indexOf(':') + 1);

    if (!contact_username || contact_username.length > 255) {
        return res.status(400).end();
    };

    MySQL.query(
        `SELECT username, BIN_TO_UUID(uuid, 1) AS uuid FROM skype_users WHERE username = ? LIMIT 1`,
        [contact_username],
        (error, users) => {
            if (error) return res.status(500).end();
            if (!users?.length || !users[0].uuid) return res.status(404).end();

            const contact = users[0];
            if (contact.uuid.toLowerCase() === verify.uuid.toLowerCase()) {
                return res.status(400).end();
            };

            MySQL.query(
                `INSERT INTO skype_contacts (owner_uuid, contact_uuid, relation_type, authorized, blocked, greeting)
                VALUES (UUID_TO_BIN(?, 1), UUID_TO_BIN(?, 1), 'invite', FALSE, FALSE, ?)`,
                [verify.uuid,contact.uuid,greeting.slice(0, 1000)],
                error => {
                    if (error?.code === 'ER_DUP_ENTRY') return res.status(200).end();
                    if (error) return res.status(500).end();

                    void notify_trouter_invite(contact.uuid);
                    return res.status(200).end();
                }
            );
        }
    );
});

api.put('/contacts/v2/users/self/invites/:mri/accept', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success || !verify.uuid) return res.status(401).end();

    const match = /^(?:8|16):(.+)$/.exec(req.params.mri ?? '');

    if (!match || !match[1].trim() || match[1].length > 255) {
        return res.status(400).end();
    };

    const sender_username = match[1];

    MySQL.query(
        `SELECT username, BIN_TO_UUID(uuid, 1) AS uuid
         FROM skype_users
         WHERE username = ?
         LIMIT 1`,
        [sender_username],
        (error, users) => {
            if (error) {
                return res.status(500).end();
            };

            if (!users?.length || !users[0].uuid) {
                return res.status(404).end();
            };

            const sender = users[0];

            if (
                sender.uuid.toLowerCase() ===
                verify.uuid.toLowerCase()
            ) {
                return res.status(400).end();
            };

            MySQL.getConnection((error, connection) => {
                if (error) {
                    return res.status(500).end();
                };

                const fail = status => {
                    connection.rollback(() => {
                        connection.release();
                        return res.status(status).end();
                    });
                };

                connection.beginTransaction(error => {
                    if (error) {
                        connection.release();
                        return res.status(500).end();
                    };

                    connection.query(
                        `SELECT 1
                         FROM skype_contacts
                         WHERE owner_uuid = UUID_TO_BIN(?, 1)
                           AND contact_uuid = UUID_TO_BIN(?, 1)
                           AND relation_type = 'invite'
                         FOR UPDATE`,
                        [sender.uuid, verify.uuid],
                        (error, invites) => {
                            if (error) {
                                return fail(500);
                            };

                            if (!invites?.length) {
                                return fail(404);
                            };

                            connection.query(
                                `UPDATE skype_contacts
                                 SET relation_type = 'contact',
                                     authorized = TRUE,
                                     greeting = NULL
                                 WHERE owner_uuid = UUID_TO_BIN(?, 1)
                                   AND contact_uuid = UUID_TO_BIN(?, 1)
                                   AND relation_type = 'invite'`,
                                [sender.uuid, verify.uuid],
                                error => {
                                    if (error) {
                                        return fail(500);
                                    };

                                    connection.query(
                                        `INSERT INTO skype_contacts (
                                            owner_uuid,
                                            contact_uuid,
                                            relation_type,
                                            authorized,
                                            blocked
                                        )
                                        VALUES (
                                            UUID_TO_BIN(?, 1),
                                            UUID_TO_BIN(?, 1),
                                            'contact',
                                            TRUE,
                                            FALSE
                                        )
                                        ON DUPLICATE KEY UPDATE
                                            relation_type = 'contact',
                                            authorized = TRUE,
                                            greeting = NULL`,
                                        [verify.uuid, sender.uuid],
                                        error => {
                                            if (error) {
                                                return fail(500);
                                            };

                                            connection.commit(error => {
                                                if (error) {
                                                    return fail(500);
                                                };

                                                connection.release();
                                                return res.status(200).end();
                                            });
                                        }
                                    );
                                }
                            );
                        }
                    );
                });
            });
        }
    );
});

api.get('/v2.0/search', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    const { searchString } = req.query;
    
    if (!skypetoken) return res.status(400).end();
    if (typeof searchString !== 'string' || !searchString.trim()) {
        return res.status(200).json({ results: [] });
    };

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify?.success) return res.status(401).end();
    
    MySQL.query(
        'SELECT username, first_name, last_name, country FROM skype_users WHERE username LIKE ? OR first_name LIKE ? OR last_name LIKE ? ORDER BY username LIMIT 50',
        [`%${searchString.trim()}%`, `%${searchString.trim()}%`, `%${searchString.trim()}%`],
        (error, users) => {
            if (error) return res.status(500).end();
            if (!users || users.length === 0) return res.status(200).json({results:[]});
            
            return res.status(200).json({
                results: users.map(user => ({
                    nodeProfileData: {
                        skypeId: user.username,
                        name: skype_crypto.get_fullname(user) || user.username,
                        countryCode: user.country || '',
                        contactType: 'Skype4Consumer'
                    },
                    nodeConnectionData: {
                        mutualFriendCount: 0
                    }
                }))
            });
        }
    );
});

const skype_api_config = {
    host: process.env.skype_api_host,
    port: parseInt(process.env.skype_api_port)
};

https_server.listen(skype_api_config.port, skype_api_config.host, () => {
    process.title = 'Skype API Server';
    logger.info(`Skype API Server is running on: https://${skype_api_config.host}:${skype_api_config.port}`);
    logger.info(`Waiting for connections...`);
});
