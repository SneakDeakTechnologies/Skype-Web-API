import functions from "../functions/functions.js";
import logger from "../logger/logger.js";

function write(client, socket, data) {
    const time = functions.get_time();

    socket.write(data);
    logger.info(`\n[INFO] ${time} << ${data}`);
};

function destroy(socket) {
    socket.destroy();
};

function end(socket) {
    socket.end();
};

export default {
    write,
    destroy,
    end
};
