/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const _ = require('lodash');

const { SERVER_COMMAND, SEVERE } = require('../../../sec-agent-constants');
const UnsupportedAgentHandler = require('./unsupported-agent-handler');
const StartupHandshakeHandler = require('./startup-handshake-handler');
const FuzzRequestHandler = require('./fuzz-request-handler');
const CollectorPolicyHandler = require('./collector-policy-handler');
const CollectorPolicyErrorHandler = require('./collecotor-policy-error-handler');
const NoOpHandler = require('./no-op-handler');
const WSReconnect = require('./ws-reconnect');
const coolDown = require('./iast-cool-down');
const recordDeletion = require('./iast-record-deletion');
const logs = require('../../../logging');
let logger = logs.getLogger();
const LogMessage = require('../../../LogMessage');

const commandHandlerMap = {
    [SERVER_COMMAND.STARTUP_WELCOME_MSG]: StartupHandshakeHandler,
    [SERVER_COMMAND.UNSUPPORTED_AGENT]: UnsupportedAgentHandler,
    [SERVER_COMMAND.FUZZ_REQUEST]: FuzzRequestHandler,
    [SERVER_COMMAND.COLLECTOR_CONFIG]: CollectorPolicyHandler,
    [SERVER_COMMAND.POLICY_ERROR]: CollectorPolicyErrorHandler,
    [SERVER_COMMAND.OBEY_WS_RECONNECT]: WSReconnect,
    [SERVER_COMMAND.IAST_RECORD_DELETE_CONFIRMATION]:recordDeletion,
    [SERVER_COMMAND.ENTER_IAST_COOLDOWN]:coolDown
};

const handle = function handle (json) {
    try {
        if (json && json.controlCommand && json.arguments && commandHandlerMap[json.controlCommand]) {
            logger.debug("Incoming Control Command:", JSON.stringify(json));
            commandHandlerMap[json.controlCommand].handler.call(this, json);
        } else {
            NoOpHandler.handler.call(this, json);
        }
    } catch (error) {
        logger.error("Error in handling Control Command",error);
        const logMessage = new LogMessage.logMessage(SEVERE, 'Error in handling Control Command', __filename, error);
        require('../../../commonUtils').addLogEventtoBuffer(logMessage);
    }
    
};

const setLogger = function setLogger (logger) {
    _.forEach(commandHandlerMap, (handler) => {
        handler.setLogger(logger);
    });
    NoOpHandler.setLogger(logger);
};

module.exports = {
    StartupHandshakeHandler,
    FuzzRequestHandler,
    UnsupportedAgentHandler,
    handle,
    setLogger
};
