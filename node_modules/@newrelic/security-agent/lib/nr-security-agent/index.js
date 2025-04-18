/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */
const API = require('../nr-security-api');
const NRAgent = API.getNRAgent();

const logs = require('./lib/core/logging');
const logger = logs.getLogger();
const initLogger = logs.getInitLogger();
const { Agent } = require('./lib/core/agent');

const agentConfig = require('./resources/config');
const shaSizeUtil = require('./lib/core/sha-size-util');
const njsAgentConstants = require('./lib/core/sec-agent-constants');

const NRLogger = API.newrelic.shim.logger.child({ component: 'security-agent' });
NRLogger.info("Starting New Relic Node.js Security Agent ");
try {
    if (NRAgent.config.security.enabled) {
        require('../instrumentation-security');
    }
} catch (error) {
    logger.error("Error while applying security instrumentation")
}

const {
    IS_LAMBDA_ENV,
    AWS_LAMBDA_FUNCTION_NAME_ENV_IDENTIFIER,
    LAMBDA_TASK_ROOT_ENV_IDENTIFIER,
    LOG_MESSAGES, SLASH } = njsAgentConstants;
const commonUtils = require('./lib/core/commonUtils');

const { AGENT_DIR } = agentConfig;
// eslint-disable-next-line no-unused-vars
const DIR_IDENTIFIER = SLASH;
const SPACE_CHARACTER = ' ';
// eslint-disable-next-line no-control-regex
const NULL_CHAR_REGEX = /\u0000/g;

const wsClient = require('./lib/core/websocket-client');


function extractApplicationDefForLambda(applications) {
    const application = {
        deployedPath: process.env[LAMBDA_TASK_ROOT_ENV_IDENTIFIER],
        appName: process.env[AWS_LAMBDA_FUNCTION_NAME_ENV_IDENTIFIER],
        contextPath: '/'
    };
    applications.push(application);
    return true;
}

/**
 * Extracts application path and name from exec args
 *
 * @param {*} execArgs
 * @param {*} applications
 */
function extractApplicationDef(execArgs, applications) {
    if (IS_LAMBDA_ENV) {
        return extractApplicationDefForLambda(applications);
    }
    if (!(Array.isArray(execArgs) && Array.isArray(applications))) {
        return false;
    }

    const entryFile = process.argv[1];
    if (entryFile) {
        execArgs = [];
        const absolutePath = require('path').resolve(entryFile);
        execArgs.push(absolutePath);
    }
    for (const arg of execArgs) {
        const application = {};
        const fileList = arg.split(DIR_IDENTIFIER);
        if (fileList.length >= 2) {
            const scriptName = fileList.pop();
            const appPath = fileList.join(DIR_IDENTIFIER);
            application.deployedPath = appPath;
            const appName = fileList.pop();
            const finder = require('find-package-json');
            const find = finder(appPath);
            const obj = find.next().value;
            if (obj && obj.__path) {
                const onlyPath = require('path').dirname(obj.__path);
                application.deployedPath = onlyPath;
                application.contextPath = '/';
            }

            application.appName = appName.concat(DIR_IDENTIFIER, scriptName);
            applications.push(application);
            break;
        } else {
            return false;
        }
    }
    return true;
}

/**
 * Initialize the Agent.
 */
function initialize() {
    initLogger.info("[STEP-1] => Security Agent is starting")
    const policyManager = require('./lib/core/Policy');
    policyManager.setDefaultPolicy();
    commonUtils.initialSetup();

    const applicationInfoModule = require('./lib/core/applicationinfo');
    const agentStatus = require('./lib/core/agent-status');
    const applications = [];
    // Initialize ApplicationInfo
    const applicationInfo = applicationInfoModule.getInstance();
    applicationInfoModule.setBuildDetails(AGENT_DIR, applicationInfo);
    initLogger.info("[STEP-3] => Gathering information about the application :", JSON.stringify(applicationInfo));
    if (NRAgent) {
        NRAgent.on('started', () => {
            NRLogger.info("Started New Relic Node.js Security Agent");
            logger.info('NR Agent started with agent_run_id:', NRAgent.config.run_id, NRAgent.config.account_id);
            if (Agent.getAgent().status.getStatus() != 'connecting') {
                Agent.getAgent().delayed = false;
                wsClient.obeyReconnect();
                return;
            }
            if (NRAgent.config.security.enabled || !NRAgent.config.high_security) {
                let delayFromConfig = parseInt(NRAgent.config.security.scan_schedule.delay);
                let delay = delayFromConfig;
                if (isNaN(delay) || delay < 0) {
                    delay = 0;
                }
                NRAgent.config.security.scan_schedule.delay = delay;
                const allowSampling = NRAgent.config.security.scan_schedule.always_sample_traces;

                if (delay >= 0) {
                    logger.debug("IAST delay is set to:", delay);
                    logger.info("Security Agent delay scan time is set to:", commonUtils.getScheduledScanTime(delay))
                    Agent.getAgent().delayed = true;
                    setTimeout(() => {
                        Agent.getAgent().delayed = false;
                        logger.info("IAST scanning delay of %s minutes over", delay);
                        commonUtils.honourDurationConfiguration();
                        commonUtils.executeCronSchedule();
                        if (!allowSampling) {
                            wsClient.initialize();
                            Agent.getAgent().status.setStatus('connecting');
                            Agent.setNRAgent(NRAgent);
                        }
                    }, delay * 60000);
                }
                logger.info("Security Agent is running with config:", JSON.stringify(NRAgent.config.security));
                if (allowSampling) {
                    wsClient.initialize();
                    Agent.getAgent().status.setStatus('connecting');
                    Agent.setNRAgent(NRAgent);
                }
                
            }
            else {
                logger.warn("security.enabled flag is set to false");
                NRLogger.warn("Failed to Start New Relic Node.js Security Agent. Please check security.enabled and high_security flags");
            }
        });
    }


    // Fallback extract with process.argv in case application is not detected using proc cmdline
    if ((extractApplicationDef(getProcCMDLineSanitized(applicationInfoModule), applications) || extractApplicationDef(process.argv, applications)) &&
        applications.length > 0) {

        if (applicationInfo && applicationInfo.runCommand) {
            const fileList = applicationInfo.runCommand.split(SPACE_CHARACTER);
            const scriptName = fileList.pop();
            if (scriptName.includes(AGENT_DIR)) {
                return false;
            }
        }
        logger.info(LOG_MESSAGES.AGENT_INFO, applicationInfo.collectorVersion, applicationInfo.jsonVersion, applicationInfo.buildNumber);

        applicationInfoModule.addProperty('serverInfo.deployedApplications', applications);

        shaSizeUtil.setLogger(logger);

        // Initialize Agent Status
        const status = agentStatus.getInstance();

        // Initialize
        Agent.init(applicationInfo, logger, wsClient, status);
        logger.info('Security Agent attached with application, with applicationUUID: %s', applicationInfo.applicationUUID);
    } else {
        // Do not load the agent.
        logger.error('Security Agent not loaded with this application: Skipped.');
        initLogger.error(LOG_MESSAGES.AGENT_INIT_FAILED);

        return false;
    }

    return true;
}

function getProcCMDLineSanitized(applicationInfoModule) {
    const proc = (applicationInfoModule.getCmdLine() || '').replace(NULL_CHAR_REGEX, SPACE_CHARACTER).trim();
    return (proc && proc.length > 0) ? proc.split(/\s/g) : process.argv;
}

(() => {
    if (!NRAgent.config.security.enabled) {
        logger.warn("security.enabled flag is set to false");
        return;
    }
    if (initialize()) {
        initLogger.info("[STEP-6] => Application instrumentation applied successfully");
    }
})();
