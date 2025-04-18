/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const fs = require('fs');

const log4js = require('log4js');
const { ENV: env } = require('../../resources/config');

const INFO = 'info';
const LOG_FILE_SIZE = 50485760 * 10000;
const LOG_PATTERN_OBJ = {
    type: 'pattern',
    pattern: '%[%d[%p][%c][%h][%z]%] %m'
};
const { LOG_DIR, CSEC_HOME } = require('./sec-agent-constants');
let logger;
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();

const logFileName = `${LOG_DIR}node-security-collector.log`;
const initLogFileName = `${LOG_DIR}node-security-collector-init.log`;
let isLoggerOk = true;
const validLogLevels = ["trace", "debug", "info", "warn", "error", "mark", "fatal", "off", "all"];
const sep = require('path').sep;
const CSEC_ROOT = `${CSEC_HOME}${sep}nr-security-home${sep}`;

function createLogPathIfNotExist(dir) {
    try {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, 770, { recursive: true });
            fs.chmodSync(dir, 0o770);
        }
        else {
            fs.chmodSync(dir, 0o770);
        }
    } catch (error) {
    }
}

/**
 * Initializes the logger appenders.
 * @param {v4uuid} applicationUUID
 */
function initialize(applicationUUID) {
    try {
        let logLevel = NRAgent && NRAgent.config && NRAgent.config.logging.enabled ? NRAgent.config.logging.level : 'info';
        const apmLogFilePath = NRAgent && NRAgent.config && NRAgent.config.logging.enabled ? NRAgent.config.logging.filepath : '';
        let appenderType = 'file';

        if (apmLogFilePath === 'stdout' || apmLogFilePath === 'stderr') {
            appenderType = 'stdout';
        }

        if (logLevel && !validLogLevels.includes(logLevel.toLowerCase())) {
            logLevel = 'info';
        }
        const appenders = {};
        appenders.NR_CSEC = {
            type: appenderType,
            compress: false,
            layout: LOG_PATTERN_OBJ
        };
        appenders.NR_CSEC_INIT = {
            type: appenderType,
            compress: false,
            layout: LOG_PATTERN_OBJ
        };


        createLogPathIfNotExist(CSEC_HOME);
        createLogPathIfNotExist(CSEC_ROOT);
        createLogPathIfNotExist(LOG_DIR);


        Object.assign(appenders.NR_CSEC, {
            filename: logFileName,
            maxLogSize: LOG_FILE_SIZE,
            backups: 0
        });

        Object.assign(appenders.NR_CSEC_INIT, {
            filename: initLogFileName,
            maxLogSize: LOG_FILE_SIZE,
            backups: 0
        });

        const categories = {
            default: {
                appenders: [
                    'NR_CSEC'
                ],
                level: logLevel
            },
            NR_CSEC_INIT: {
                appenders: [
                    'NR_CSEC_INIT',
                ],
                level: logLevel
            },
        };

        if (apmLogFilePath !== 'stdout') {
            categories.NR_CSEC_INIT.appenders.push('NR_CSEC')
        }


        if (env === 'dev' || env === 'trace') {
            appenders.STDOUT = {
                type: 'stdout',
                layout: LOG_PATTERN_OBJ
            };
            categories.default.appenders.push('STDOUT');
            categories.NR_CSEC_INIT.appenders.push('STDOUT');
        }

        log4js.configure({
            appenders: appenders,
            categories: categories,
            disableClustering: true
        });
    } catch (error) {
        console.error(`Security agent is unable to write logs into file: ${logFileName}.`, error.message);
        isLoggerOk = false;
    }
}

/**
 * sets the logging level of current instance.
 * @param {String} level
 */
function setLevel(level = INFO) {
    level = level.trim();
    if (logger) {
        logger.level = level;
    }
    if (!isLoggerOk) {
        logger.level = "off";
    }
}

/**
 * get the logging level of current instance.
 */
function getLevel() {
    if (logger) {
        return logger.level;
    } else {
        throw new Error('CSEC-Loggers Not yet Initialized!');
    }
}

/**
 * Returns an instance of Loggers.
 * Initializes an instace if not instance is
 * already made.
 * @param {v4uuid} applicationUUID
 */
function getLogger(applicationUUID = process.env.applicationUUID) {
    if (logger) {
        return logger;
    }
    if (applicationUUID) {
        initialize(applicationUUID);
        logger = log4js.getLogger('NR_CSEC');
        const initLogger = getInitLogger();
        try {
            fs.chmodSync(`${logFileName}`, 0o660);
            fs.chmodSync(`${initLogFileName}`, 0o660);
        } catch (error) {
        }
        initLogger.info("[STEP-2] => Generating unique identifier:", applicationUUID)
        if (NRAgent && NRAgent.config.logging.enabled) {
            setLevel(NRAgent.config.logging.level);
        }

        return logger;
    } else {
        throw new Error('applicationUUID is required to initialize loggers.');
    }
}

function reCreateLogger(applicationUUID) {
    initialize(applicationUUID);
    logger = log4js.getLogger('NR_CSEC');
    setLevel(logger.level);
    updateModuleLoggers(logger);
}

function getInitLogger() {
    const initLogger = log4js.getLogger('NR_CSEC_INIT');
    return initLogger;
}



module.exports = {
    getLogger,
    setLevel,
    getLevel,
    getInitLogger,
    reCreateLogger,
    isLoggerOk
};
