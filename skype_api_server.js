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
        logger.debug(`[MySQL] Successful MySQL Connection`);
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
api.use(express.json());
api.use(express.urlencoded({ extended: true }));
api.use(express.raw({ 
    type: ['image/png', 'image/jpeg', 'image/jpg', 'application/octet-stream'], 
    limit: '10mb' 
}));
api.use(express.static(path.join(__dirname, 'public')));

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
                    const refresh_token = skype_crypto.generate_refresh_token();

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
    if (!verify.success) return res.status(401);

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

api.get('/users/self/profile', async (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify.success) return res.status(401).end();

    try {
        const user = await skype_crypto.getUserByUUID(verify.uuid, MySQL);
        if (!user) return res.status(404).end();

        return res.status(200).json({
            firstname: user.first_name,
            lastname: user.last_name,
            mood: user.mood,
            phoneMobile: user.phoneMobile,
            phoneHome: user.phoneHome,
            phoneOffice: user.phoneOffice,
            emails: [],
            country: user.country,
            city: user.city,
            homepage: user.homepage,
            gender: user.gender,
            birthday: user.birthday,
            language: user.language,
            about: user.about,
        });
    } catch (error) {
        return res.status(500).end();
    };
});

api.post('/users/self/profile/partial', (req, res) => {
    const skypetoken = req.headers['x-skypetoken'];
    const { username } = req.params;
    if (!skypetoken) return res.status(400).end();

    const verify = skype_crypto.verify_skypetoken(skypetoken);
    if (!verify.success) return res.status(401).end();
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

const skype_api_config = {
    host: process.env.skype_api_host,
    port: parseInt(process.env.skype_api_port)
};

https_server.listen(skype_api_config.port, skype_api_config.host, () => {
    process.title = 'Skype API Server';
    logger.info(`Skype API Server is running on: https://${skype_api_config.host}:${skype_api_config.port}`);
    logger.info(`Waiting for connections...`);
});