/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

/* eslint-disable prefer-promise-reject-errors */
const fs = require('fs');
const uuidV = require('uuid');
const logs = require('./logging');
const logger = logs.getLogger();
const OS = require('os');
const path = require('path');
const checkDiskSpace = require('check-disk-space').default;
const AgentStatus = require('../core/agent-status');
const { CSEC_HOME, SLASH, EMPTY_STR } = require('./sec-agent-constants');

const njsAgentConstants = require('./sec-agent-constants');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();
const lodash = require('lodash')
const backupLogFileRegex = /.log.\d/gm;
let websocketHealth;

const ringBuffer = require('ringbufferjs');
const bufferedLogEvents = new ringBuffer(10);
const { CronJob } = require('cron');
let scanStartTime = 0;
let trafficStartedTime = 0;
const cron = require('cron');

const skip_detection_category_map = {
    insecure_settings: ['CRYPTO', 'HASH', 'RANDOM', 'SECURE_COOKIE', 'TRUSTBOUNDARY'],
    invalid_file_access: ['FILE_OPERATION', 'FILE_INTEGRITY'],
    sql_injection: ['SQL_DB_COMMAND'],
    nosql_injection: ['NOSQL_DB_COMMAND'],
    ldap_injection: ['LDAP'],
    javascript_injection: ['JS_INJECTION'],
    command_injection: ['SYSTEM_COMMAND'],
    xpath_injection: ['XPATH'],
    ssrf: ['HTTP_REQUEST'],
    rxss: ['REFLECTED_XSS']
}


/**
 * Utility to generate UUID
 * @returns UUID
 */
function getUUID() {
    let uuid = process.env.applicationUUID || uuidV.v4();
    process.env.applicationUUID = uuid;
    return uuid;
}

function getKindIdPair(identifier, hostId) {
    const obj = {};
    if (identifier.isContainer) {
        obj.first = 'CONTAINER';
        obj.second = identifier.containerId;
    } else if (identifier.isECSContainer) {
        obj.first = 'ECS';
        obj.second = identifier.ecsTaskId;
    } else if (identifier.isPod) {
        obj.first = 'CONTAINER';
        obj.second = identifier.podId;
    } else {
        obj.first = 'HOST';
        obj.second = hostId;
    }
    return obj;
}

/**
 * Utility to check worker thread support
 * @returns 
 */
function hasWorker() {
    let workerFlag = false;
    try {
        require('worker_threads');
        workerFlag = true;
    } catch (error) {
        workerFlag = false;
    }
    return workerFlag;
}

function runtimeSupportsFunctionGenerators() {
    try {
        // eslint-disable-next-line no-eval
        eval('"use strict"; (function* () {})');
        process.csecRuntimeSupportsFunctionGenerators = true;
    } catch (err) {
        process.csecRuntimeSupportsFunctionGenerators = false;
    }
    return process.csecRuntimeSupportsFunctionGenerators;
}

function runtimeSupportsAsyncFunctionGenerators() {
    try {
        // eslint-disable-next-line no-eval
        eval('"use strict"; (async function* () {})');
        process.csecRuntimeSupportsAsyncFunctionGenerators = true;
    } catch (err) {
        process.csecRuntimeSupportsAsyncFunctionGenerators = false;
    }
    return process.csecRuntimeSupportsAsyncFunctionGenerators;
}

/**
 * Utility to create directory and set permissions
 * @param {*} dir 
 */
function createPathIfNotExist(dir) {
    try {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, 770, { recursive: true });
            logger.info(dir + ' Created');
            fs.chmodSync(dir, 0o770);
        } else {
            fs.chmodSync(dir, 0o770);
            logger.debug(dir + ' Already Exists');
        }
    } catch (error) {
        logger.debug(dir + ' Not Created', error);
        const LogMessage = require('./LogMessage');
        const logMessage = new LogMessage.logMessage("DEBUG", 'Error in creating directory', __filename, error);
        addLogEventtoBuffer(logMessage);
    }
}

/**
 * Utility to get OS
 * @returns 
 */
function getOS() {
    if (process.platform === 'darwin') {
        return 'mac';
    }
    if (process.platform === 'win32') {
        return 'windows';
    } else {
        return 'linux';
    }
}

/**
 * Utility to create directories
 */
function createDirectories() {
    createPathIfNotExist(`${CSEC_HOME}${SLASH}nr-security-home`);
    createPathIfNotExist(`${CSEC_HOME}${SLASH}nr-security-home${SLASH}logs`);
    createPathIfNotExist(`${CSEC_HOME}${SLASH}nr-security-home${SLASH}tmp`);
    createPathIfNotExist(`${CSEC_HOME}${SLASH}nr-security-home${SLASH}tmp${SLASH}language-agent`);
    createPathIfNotExist(`${CSEC_HOME}${SLASH}nr-security-home${SLASH}tmp${SLASH}language-agent${SLASH}${getUUID()}`);
    createPathIfNotExist(`${CSEC_HOME}${SLASH}nr-security-home${SLASH}tmp${SLASH}language-agent${SLASH}${getUUID()}${SLASH}ds-tmp`);
    try {
        fs.chmodSync(`${CSEC_HOME}${SLASH}nr-security-home`, 0o770);
    } catch (error) {
    }
}
/**
 * Utility to check init setup and disk space
 */
async function initialSetup() {
    try {
        createDirectories();
    } catch (err) {
        logger.error(err);
    }
}

/**
 * Utility function to check if the logfile is accessible or not.
 */
function isLogAccessible(logFileName) {
    return new Promise((resolve) => {
        fs.access(logFileName, fs.constants.F_OK | fs.constants.W_OK, (err) => {
            if (err) {
                resolve('Error');
            }
            else if ((!logs.isLoggerOk || logger.level.levelStr == 'OFF')) {
                resolve('Error');
            }
            else {
                resolve('OK');
            }
        });
    }).catch(() => {
    });
}


/**
 * Utility function to get CPU Usage in percentage
 * @param {*} oldUsage
 */
function getCpuUsage() {
    const usageObj = process.cpuUsage();
    const userUsage = usageObj.user / (usageObj.user + usageObj.system);
    return userUsage;
}

/**
 * Utility to convert Bytes to MB
 * @param {*} bytes
 * @param {*} decimals
 */
function formatBytesToMB(bytes, decimals = 2) {
    return parseFloat((bytes / (1024 * 1024)).toFixed(decimals));
}

/**
 * Utility to get diskSpace infor for the give path
 * @param {*} path
 */
async function getDiskSpace(path) {
    try {
        const x = await checkDiskSpace(path).catch(() => { });
        return x;
    } catch (error) {
        logger.error("Error in getting diskpace:", error)
    }
}

/**
 * Utility to get HC stats
 */
async function getHCStats() {
    const stats = {};
    try {
        const appInfo = require('./applicationinfo').getInstance();
        const rootDiskSpace = await getDiskSpace(path.parse(process.cwd()).root);
        if (appInfo && appInfo.serverInfo && appInfo.serverInfo.deployedApplications[0] && appInfo.serverInfo.deployedApplications[0].deployedPath) {
            const processDirDiskFreeSpace = await getDiskSpace(appInfo.serverInfo.deployedApplications[0].deployedPath);
            if (processDirDiskFreeSpace) {
                stats.processDirDiskFreeSpaceMB = formatBytesToMB(processDirDiskFreeSpace.free);
            }
        }
        const memoryObj = process.memoryUsage();
        if (rootDiskSpace) {
            stats.rootDiskFreeSpaceMB = formatBytesToMB(rootDiskSpace.free);
        }

        stats.processHeapUsageMB = formatBytesToMB(memoryObj.heapUsed);
        stats.processRssMB = formatBytesToMB(memoryObj.rss);
        stats.processMaxHeapMB = formatBytesToMB(memoryObj.heapTotal);
        stats.systemFreeMemoryMB = formatBytesToMB(OS.freemem());
        stats.systemTotalMemoryMB = formatBytesToMB(OS.totalmem());
        stats.nCores = OS.cpus().length;
        stats.processCpuUsage = parseFloat(getCpuUsage().toFixed(2));
        stats.systemCpuLoad = parseFloat(OS.loadavg()[1].toFixed(2));
    } catch (error) {
        logger.error('Error in generating stats:', error);
    }
    return stats;
}
/**
 * Utility to check Agent status
 */
function isAgentActiveState() {
    if (AgentStatus.getInstance().getStatus() === AgentStatus.CSECAgentStatus.codes.ACTIVE && (NRAgent ? (NRAgent.config.security.enabled && NRAgent.canCollectData()) : true) && getWSHealthStatus() == 'OK') {
        return 'OK';
    } else {
        return 'Error';
    }
}

function iastRestClientStatus() {
    return 'OK';
}
/**
 * Utilty to remove older log files.
 */
function removeOlderlogfiles() {
    try {
        const basePath = njsAgentConstants.LOG_DIR;
        const directoryContent = fs.readdirSync(basePath);
        // eslint-disable-next-line array-callback-return
        const files = directoryContent.filter((filename) => {
            if (filename.match(backupLogFileRegex)) {
                return fs.statSync(`${basePath}${SLASH}${filename}`).isFile();
            }
        });
        const sorted = files.sort((a, b) => {
            const firstStat = fs.statSync(`${basePath}${SLASH}${a}`);
            const secondStat = fs.statSync(`${basePath}${SLASH}${b}`);
            return new Date(secondStat.mtime).getTime() - new Date(firstStat.mtime).getTime();
        });
        let maxLogfile = process.env.NR_CSEC_DEBUG_LOGFILE_MAX_COUNT;
        if (isNaN(maxLogfile)) {
            maxLogfile = 2;
        }
        for (let i = maxLogfile; i < sorted.length; i++) {
            const fileToDelete = basePath + sorted[i];
            try {
                fs.unlink(fileToDelete, (err) => {
                    if (err) {
                        logger.error(err);
                    } else {
                        logger.debug('Logfile deleted:', fileToDelete);
                    }
                });
            } catch (error) {
                logger.error(error);
            }
        }
    } catch (error) {
        logger.debug(error);
    }
}

/**
 * utilty to roll over the log file. Not in use
 */
function logRollOver() {
    const logFileName = `${njsAgentConstants.LOG_DIR}node-security-collector.log`;
    try {
        const stats = fs.statSync(logFileName);
        if (stats.size < 50485760) {
            return;
        }
    } catch (error) {
        logger.debug('Error in getting stats of log file:', error.message);
        return;
    }

    try {
        const lockFile = `${njsAgentConstants.LOG_DIR}lock-file.lock`;
        const pid = process.pid;
        if (!fs.existsSync(lockFile)) {
            fs.writeFileSync(lockFile, pid.toString());
        }
        const fileData = fs.readFileSync(lockFile).toString();
        if (pid.toString() === fileData) {
            try {
                const newLogFile = logFileName + '.' + Date.now();
                fs.copyFileSync(logFileName, newLogFile);
                fs.truncateSync(logFileName);
                logger.info('logfile rolled over successfully', newLogFile);
                removeOlderlogfiles();
            } catch (error) {
                logger.error(error);
            }
        }
        fs.unlinkSync(lockFile);
    } catch (error) {
        logger.error(error);
    }
}

/**
 * Utility to get validator service endpoint
 * @returns 
 */
function getValidatorServiceEndpointURL() {
    let validatorServiceEndpointURL = NRAgent ? NRAgent.config.security.validator_service_url : "wss://csec.nr-data.net";
    if (lodash.isEmpty(validatorServiceEndpointURL)) {
        validatorServiceEndpointURL = "wss://csec.nr-data.net";
    }
    return validatorServiceEndpointURL
}

/**
 * Utility to get security mode
 * @returns 
 */
function getCSECmode() {
    const mode = NRAgent ? NRAgent.config.security.mode : 'IAST';
    return mode
}

/**
 * Utility to get path of CA Cert
 * @returns 
 */
function getPathOfCACert() {
    let relativePath = path.resolve(__dirname, '../../resources/cert.pem');
    if (process.platform == 'win32') {
        relativePath = path.resolve(__dirname, '..\\..\\resources\\cert.pem');
    }
    const certPath = NRAgent && NRAgent.config.security.ca_bundle_path ? NRAgent.config.security.ca_bundle_path : relativePath;
    return certPath
}
/**
 * Setting ws health status
 * @param {*} status 
 */
function setWSHealthStatus(status) {
    websocketHealth = status;
}

/**
 * Returns value of websocketHealth
 * @returns websocketHealth
 */
function getWSHealthStatus() {
    if (!websocketHealth) {
        return 'Error';
    }
    else {
        return websocketHealth;
    }
}

/**
 * return buffered Log Event instance.
 */
function getLogEvents() {
    return bufferedLogEvents;
}


/**
 * Utility to add error object in error buffer
 * @param {*} error
 */
function addLogEventtoBuffer(logMessage) {
    try {
        bufferedLogEvents.enq(logMessage);
    } catch (error) {
        logger.debug(error);
    }
}
/**
 * Utility to get framework from APM
 * @returns 
 */
function getFramework() {
    let framework = EMPTY_STR;
    try {
        framework = NRAgent.environment.get('Framework')[0];
    } catch (error) {
        logger.debug("Unable to get framework");
    }
    return framework;
}

function listSkipDetectionCategory() {
    let skipList = [];
    try {
        let skipCataegories = NRAgent.config.security.exclude_from_iast_scan.iast_detection_category;
        for (const key in skipCataegories) {
            if (skipCataegories[key]) {
                skipList = skipList.concat(skip_detection_category_map[key]);
            }
        }
    } catch (error) {
        logger.error("Error while processing skip detection categories:", error);
    }
    return skipList;
}

function refreshAgent() {
    const { Agent } = require('./agent');
    if (Agent.getAgent().status.getStatus() == 'disabled' || Agent.getAgent().delayed) {
        Agent.getAgent().delayed = false;
        const wsClient = Agent.getAgent().client;
        Agent.getAgent().status.setStatus('connecting');
        wsClient.obeyReconnect();
        honourDurationConfiguration();
    }
}

function executeCronSchedule() {
    try {
        let schedule = NRAgent.config.security.scan_schedule.schedule;
        if (lodash.isEmpty(schedule)) {
            return;
        }
        logger.debug("Schedule config is set to:", schedule);
        schedule = schedule.replace(/\?/g, '*');
        logger.info("Security Agent scheduled time is set to:", getScheduledScanTime(Math.ceil(cron.timeout(schedule) / 60000)))
        const job = new cron.CronJob(
            schedule, // cronTime
            function () {
                logger.debug('Cron schedule invoked');
                logger.info("Security Agent scheduled time is set to:", getScheduledScanTime(Math.ceil(cron.timeout(schedule) / 60000)))
                refreshAgent()
            }, // onTick
            null, // onComplete
            true, // start
        );
    } catch (error) {
        logger.error("Error while processing schedule. Please check schedule cron expression", error);
        shutDownAgent();
    }

}

function honourDurationConfiguration() {
    let durationFromConfig = parseInt(NRAgent.config.security.scan_schedule.duration);
    let duration = durationFromConfig;
    if (isNaN(duration) || duration < 0) {
        duration = 0;
    }
    logger.debug("IAST duration is set to:", duration);
    NRAgent.config.security.scan_schedule.duration = duration;
    if (duration < 1) {
        return;
    }
    logger.info("Security Agent shutdown is set to:", getScheduledScanTime(duration))
    setTimeout(() => {
        shutDownAgent();
    }, duration * 60000);
}
/**
 * Utility to send error to error inbox of APM
 * @param {*} error 
 */
function sendErrorToErrorInbox(error) {
    API.newrelic.noticeError(error);
}

const getScheduledScanTime = (delayInMinutes) => {
    // Get the current time
    const currentTime = new Date();

    // Add the given minutes to the current time
    currentTime.setMinutes(currentTime.getMinutes() + delayInMinutes);

    const year = currentTime.getFullYear();
    const month = currentTime.toLocaleString("default", { month: "long" });
    const day = currentTime.toLocaleString("default", { weekday: "long" });
    const date = currentTime.getDate();
    const hours = currentTime.getHours();
    const minutes = currentTime.getMinutes();
    const seconds = currentTime.getSeconds();
    const futureUpdatedTime = `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`;
    const futureDateTime = `${day}, ${month} ${date} ${year} ${futureUpdatedTime}`;
    return futureDateTime
};

function shutDownAgent() {
    const { Agent } = require('./agent');
    if (NRAgent.config.security.scan_schedule.always_sample_traces) {
        Agent.getAgent().delayed = true;
        logger.warn('Scan duration completed, IAST going under hibernate mode')
        return;
    }
    if (Agent.getAgent().status.getStatus() === 'disabled') {
        return;
    }
    Agent.getAgent().status.setStatus('disabled');
    const wsClient = Agent.getAgent().client;
    wsClient.closeWS();
    logger.warn("Security Agent status is disabled");
}




module.exports = {
    getUUID,
    getKindIdPair,
    hasWorker,
    runtimeSupportsFunctionGenerators,
    runtimeSupportsAsyncFunctionGenerators,
    createPathIfNotExist,
    getOS,
    initialSetup,
    createDirectories,
    isLogAccessible,
    getCpuUsage,
    getHCStats,
    isAgentActiveState,
    iastRestClientStatus,
    logRollOver,
    getValidatorServiceEndpointURL,
    getCSECmode,
    getPathOfCACert,
    getWSHealthStatus,
    setWSHealthStatus,
    addLogEventtoBuffer,
    getLogEvents,
    getFramework,
    listSkipDetectionCategory,
    executeCronSchedule,
    honourDurationConfiguration,
    scanStartTime,
    trafficStartedTime,
    sendErrorToErrorInbox,
    getScheduledScanTime,
};
