import crypto from 'crypto';

function build_msnp_packet(cmd, trId, type, payload = '') {
    if (typeof cmd !== 'string' || !cmd.length) {
        return null;
    };

    if (!Number.isInteger(trId) || trId < 0) {
        return null;
    };

    if (typeof type !== 'string' || !type.length) {
        return null;
    };

    if (typeof payload !== 'string') {
        return null;
    };

    const payload_len = Buffer.byteLength(payload, 'utf8');
    const len = payload_len + 2;

    return `${cmd} ${trId} ${type} ${len}\r\n\r\n${payload}`;
};

function build_login_ok(cmd, trId, type, username) {
    const ath_payload =
        `<auth-response>` +
        `<new-thread-allowed>false</new-thread-allowed>` +
        `<p2p-migration-allowed>false</p2p-migration-allowed>` +
        `<id>${username}</id>` +
        `</auth-response>`;

    return build_msnp_packet(cmd,  trId, type, ath_payload);
};

function build_login_fail(trId) {
    return build_msnp_packet(cmd, trId, type, "Authentication failed");
};

export function build_challenge_response(challenge) {
    const productId = 'PROD0090YUAUV{2B';
    const productKey = 'YMM8C_H7KCQ2S_KL';
    const mod = 0x7fffffffn;
    const magic = 0x0e79a9c1n;

    const md5 = crypto
        .createHash('md5')
        .update(challenge + productKey, 'utf8')
        .digest();
        
    const md5_parts = [];

    for (let i = 0; i < 4; i++) {
        md5_parts.push(
            BigInt(md5.readUInt32LE(i * 4) & 0x7fffffff)
        );
    };

    let challenge_string = challenge + productId;
    const remainder = Buffer.byteLength(challenge_string, 'utf8') % 8;

    if (remainder !== 0) {
        challenge_string += '0'.repeat(8 - remainder);
    };

    const data = Buffer.from(challenge_string, 'utf8');

    let nHigh = 0n;
    let nLow = 0n;

    for (let offset = 0; offset < data.length; offset += 8) {
        const part0 = BigInt(data.readUInt32LE(offset));
        const part1 = BigInt(data.readUInt32LE(offset + 4));

        let temp = (magic * part0) % mod;
        temp = (md5_parts[0] * (temp + nLow) + md5_parts[1]) % mod;

        nHigh += temp;
        temp = (part1 + temp) % mod;

        nLow = (md5_parts[2] * temp + md5_parts[3]) % mod;
        nHigh += nLow;
    };

    nLow = (nLow + md5_parts[1]) % mod;
    nHigh = (nHigh + md5_parts[3]) % mod;

    const output = Buffer.alloc(16);
    const keys = [nLow, nHigh, nLow, nHigh];

    for (let i = 0; i < 4; i++) {
        const md5Word = md5.readUInt32LE(i * 4);
        const value = (md5Word ^ Number(keys[i])) >>> 0;

        output.writeUInt32LE(value, i * 4);
    };

    return output.toString('hex');
};

export default {
    build_msnp_packet,
    build_login_ok,
    build_login_fail,
    build_challenge_response
};
