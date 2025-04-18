/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const StartupConfig = require('../../../startup-config');
const logs = require('../../../logging');
let logger = logs.getLogger();
const initLogger = logs.getInitLogger();
const LOG_MESSAGES = require('../../../sec-agent-constants').LOG_MESSAGES;
const applicationInfoModule = require('../../../applicationinfo');
const LogMessage = require('../../../LogMessage');
const API = require('../../../../../../nr-security-api');
const NRAgent = API.getNRAgent();
const { Agent } = require('../../../agent');


module.exports.handler = function handler(json) {
    try {
        const startupConfig = StartupConfig.getInstance();
        startupConfig.config = json.data;
      
        initLogger.info(LOG_MESSAGES.AGENT_INIT_WITH_PROP, JSON.stringify(startupConfig.config));
        initLogger.info('Security Agent is now ACTIVE for', applicationInfoModule.getInstance().applicationUUID);
        const logMessage = new LogMessage.logMessage("INFO", `Security Agent is ACTIVE for ${ applicationInfoModule.getInstance().applicationUUID}`, __filename, null);
        require('../../../commonUtils').addLogEventtoBuffer(logMessage);
       
    } catch (error) {
        logger.error(LOG_MESSAGES.PARSING_EXP_WELCOME_MSG, error);
    }
};

// eslint-disable-next-line no-unused-vars
module.exports.setLogger = l => { logger = l };
