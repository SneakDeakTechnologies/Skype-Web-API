import logger from "../logger/logger.js";

function send(ws, client, data) {
    ws.send(data);
    logger.info(`[INFO] Sent data to ${client}: ${data}`);
};

function end(ws) {
    ws.end();    
};

export default {
    send
};
