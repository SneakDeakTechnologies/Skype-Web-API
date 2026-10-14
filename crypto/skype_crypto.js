import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

dotenv.config({ 
    path: './config.env',
    quiet: true
});

const xor_key = Buffer.from(process.env.xor_key, 'hex');
const token_secret = process.env.token_secret;

const avatar_dir = path.resolve('users/avatars');
const avatar_exts = ['.png', '.jpg', '.jpeg', '.bmp'];

function base64url(buf) {
    return Buffer.from(buf)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
};

function xorMask(buf) {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        out[i] = buf[i] ^ xor_key[i % xor_key.length];
    };
    return out;
};

function generate_access_token(uuid, options) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: options.iss,
        aud: options.aud,
        sub: uuid,
        iat: now,
        exp: now + options.token_ttl,
        type: options.type,
        jti: crypto.randomUUID(),
    };

    const json = Buffer.from(JSON.stringify(payload));
    const obfuscated = xorMask(json);

    const sign = crypto.createHmac('sha256', token_secret)
        .update(obfuscated)
        .digest();

    const len = Buffer.alloc(2);
    len.writeUInt16BE(obfuscated.length);
    
    return base64url(Buffer.concat([Buffer.from([0x01]), len, obfuscated, sign]));
};

function generate_refresh_token() {
    return crypto.randomBytes(64).toString('hex');
};

function generate_skypetoken(uuid, skypename, token_ttl) {
    const payload = {
        uuid: uuid,
        skypename: skypename,
        exp: Math.floor(Date.now() / 1000) + token_ttl,
        iat: Math.floor(Date.now() / 1000)
    };

    return jwt.sign(payload, process.env.token_secret, { algorithm: 'HS256' });
};

function verify_access_token(access_token) {
    try {
        const buffer = Buffer.from(access_token.replace(/-/g, "+").replace(/_/g, "/"), "base64");
        if (buffer[0] !== 0x01) {
            return false;
        };

        const obfuscated_len = buffer.readUInt16BE(1);
        const obfuscated = buffer.subarray(3, 3 + obfuscated_len);
        const sign = buffer.subarray(3 + obfuscated_len);

        const expected_sign = crypto.createHmac("sha256", token_secret)
            .update(obfuscated)
            .digest();

        if (sign.length !== expected_sign.length || !crypto.timingSafeEqual(sign, expected_sign)) { 
            return false;
        };

        const json = xorMask(Buffer.from(obfuscated));
        const payload = JSON.parse(json.toString("utf8"));
        const now = Math.floor(Date.now() / 1000);

        if (payload.exp < now) {
            return false;
        };

        if (payload.iss !== "sda") {
            return false;
        };

        return { success: true, uuid: payload.sub };
    } catch (error) {
        return false;
    };
};

function verify_skypetoken(skypetoken) {
    try {
        const payload = jwt.verify(skypetoken, process.env.token_secret, { algorithms: ['HS256'] });

        if (!payload.uuid || !payload.skypename) {
            return false;
        };

        return { success: true, uuid: payload.uuid, skypename: payload.skypename };
    } catch (error) {
        return false;
    };
};

async function getUserByUUID(uuid, MySQL) {
    return new Promise((resolve, reject) => {
        MySQL.query(
            `SELECT
                username,
                first_name,
                last_name,
                mood,
                phoneMobile,
                phoneHome,
                phoneOffice,
                emails,
                country,
                city,
                homepage,
                gender,
                DATE_FORMAT(birthday, "%Y-%m-%d") AS birthday,
                language,
                about
             FROM skype_users
             WHERE uuid = UUID_TO_BIN(?, 1)`,
            [uuid],
            (error, users) => {
                if (error) return reject(error);
                if (!users || users.length === 0) return resolve(null);

                resolve(users[0]);
            }
        );
    });
};

async function getUUIDByUsername(username, MySQL) {
    return new Promise((resolve, reject) => {
        MySQL.query(
            'SELECT BIN_TO_UUID(uuid, 1) AS uuid FROM skype_users WHERE username = ?',
            [username],
            (error, users) => {
                if (error) return reject(error);
                if (!users || users.length === 0) return resolve(null);

                resolve(users[0].uuid);
            }
        );
    });
};

async function getUsernameByUUID(uuid, MySQL) {
    return new Promise((resolve, reject) => {
        MySQL.query(
            'SELECT username FROM skype_users WHERE uuid = UUID_TO_BIN(?, 1)',
            [uuid],
            (error, users) => {
                if (error) return reject(error);
                if (!users || users.length === 0) return resolve(null);

                resolve(users[0].username);
            }
        );
    });
};

function getAvatarByUUID(uuid) {
    if (typeof uuid !== 'string' || uuid.length === 0) return null;

    for (const ext of avatar_exts) {
        const file_path = path.join(avatar_dir, `${uuid}${ext}`);

        if (fs.existsSync(file_path)) {
            return file_path;
        };
    };

    return null;
};

function detectImageExt(buffer) {
    if (!buffer || buffer.length < 4) return null;

    if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
        return '.png';
    };

    if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
        return '.jpg';
    };

    if (buffer[0] === 0x42 && buffer[1] === 0x4D) {
        return '.bmp';
    };

    return null;
};

async function setAvatarByUUID(uuid, buf) {
    if (typeof uuid !== 'string' || uuid.length === 0) {
        return { success: false };
    };

    if (!Buffer.isBuffer(buf) || buf.length === 0) {
        return { success: false};
    };

    const ext = detectImageExt(buf);
    if (!ext) {
        return { success: false };
    };

    if (!fs.existsSync(avatar_dir)) {
        fs.mkdirSync(avatar_dir, { recursive: true });
    };

    const file_path = path.join(avatar_dir, `${uuid}${ext}`);

    for (const e of avatar_exts) {
        const old = path.join(avatar_dir, `${uuid}${e}`);
        if (old !== file_path && fs.existsSync(old)) {
            fs.unlinkSync(old);
        };
    };

    await fs.promises.writeFile(file_path, buf);
    return { path: file_path, ext };
};

function rsa_public_decrypt(uic, modulus_hex, exponent = 65537) {
    try {
        const buffer = Buffer.isBuffer(uic)
            ? Buffer.from(uic)
            : Buffer.from(uic, 'base64url');

        if (buffer.length !== 260) {
            return null;
        };

        const encrypted = buffer.subarray(4);

        const modulus = Buffer.from(modulus_hex, 'hex');

        if (modulus.length !== 256) {
            return null;
        };

        let exponent_bytes = [];
        let value = exponent;

        while (value > 0) {
            exponent_bytes.unshift(value & 0xff);
            value >>>= 8;
        };

        const key_object = crypto.createPublicKey({
            key: {
                kty: 'RSA',
                n: modulus.toString('base64url'),
                e: Buffer.from(exponent_bytes).toString('base64url')
            },
            format: 'jwk'
        });

        return crypto.publicDecrypt(
            {
                key: key_object,
                padding: crypto.constants.RSA_NO_PADDING
            },
            encrypted
        );
    }
    catch (error) {
        return null;
    };
};

function verify_uic(uic, modulus_hex, exponent = 65537) {
    try {
        const decrypted_uic = rsa_public_decrypt(
            uic,
            modulus_hex,
            exponent
        );

        if (!decrypted_uic || !Buffer.isBuffer(decrypted_uic)) {
            return { success: false };
        };

        if (decrypted_uic.length !== 256) {
            return { success: false };
        };

        if (decrypted_uic[0] !== 0x4B) {
            return { success: false };
        };

        let pos = 1;

        while (
            pos < decrypted_uic.length &&
            decrypted_uic[pos] === 0xBB
        ) {
            pos++;
        };

        if (
            pos >= decrypted_uic.length ||
            decrypted_uic[pos] !== 0xBA
        ) {
            return { success: false };
        };

        const payload_start = pos + 1;
        const sha_start = decrypted_uic.length - 21;

        if (sha_start <= payload_start) {
            return { success: false };
        };

        if (decrypted_uic[decrypted_uic.length - 1] !== 0xBC) {
            return { success: false };
        };

        const payload = decrypted_uic.subarray(
            payload_start,
            sha_start
        );

        const received_sha1 = decrypted_uic.subarray(
            sha_start,
            sha_start + 20
        );

        const calculated_sha1 = crypto
            .createHash('sha1')
            .update(payload)
            .digest();

        if (!crypto.timingSafeEqual(
            received_sha1,
            calculated_sha1
        )) {
            return { success: false };
        };

        let p = 0;

        if (payload[p++] !== 0x41) {
            return { success: false };
        };

        if (payload[p++] !== 0x05) {
            return { success: false };
        };

        if (payload[p++] !== 0x03) {
            return { success: false };
        };

        if (payload[p++] !== 0x00) {
            return { success: false };
        };

        const username_end = payload.indexOf(0x00, p);

        if (username_end === -1) {
            return { success: false };
        };

        const username = payload
            .subarray(p, username_end)
            .toString('utf8');

        if (!username.length) {
            return { success: false };
        };

        return { success: true, username };
    }
    catch (error) {
        return { success: false };
    };
};

export default {
    generate_access_token,
    generate_refresh_token,
    generate_skypetoken,
    verify_access_token,
    verify_skypetoken,
    getUserByUUID,
    getUUIDByUsername,
    getUsernameByUUID,
    getAvatarByUUID,
    setAvatarByUUID,
    verify_uic
};
