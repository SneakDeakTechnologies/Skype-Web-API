import chalk from 'chalk';

function info(message) {
    console.log(chalk.bold.cyan(message));
};

function warn(message) {
    console.log(chalk.bold.yellow(message));
};

function error(message) {
    console.log(chalk.bold.red(message));
};

export default {
    info,
    warn,
    error
};
