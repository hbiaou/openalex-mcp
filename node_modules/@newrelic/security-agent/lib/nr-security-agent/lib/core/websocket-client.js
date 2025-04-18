/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';
const LOG_MESSAGES = require('./sec-agent-constants').LOG_MESSAGES;

const { Agent } = require('./agent');
const AgentStatus = require('./agent-status');
const hc = require('./health-check');
const applicationInfo = require('./applicationinfo').getInstance();
const logger = require('./logging').getLogger(applicationInfo.applicationUUID);
const initLogger = require('./logging').getInitLogger();
const commonUtils = require('./commonUtils');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();
const LogMessage = require('./LogMessage');
const {
    SecWebSocket,
    setWebSocketConn,
    ResponseHandler: {
        setLogger: setResponseHandlerLogger
    }
} = require('./connections/websocket');
const { HC_INTERVAL_MS } = require('../../resources/config');
const { LOG_DIR, EXITEVENT, JSON_NAME } = require('./sec-agent-constants');
const njsAgentConstants = require('./sec-agent-constants');

let wsInstance;
let dispatcher;

const DEFAULT_EVENT_SEND_CB = err => {
    if (err) {
        hc.getInstance().registerEventDrop();
        logger.debug(err);
    }
};

/**
 * Initializes the Websocket connection to Validator.
 */
const initialize = function () {
    // we would want that the websocket be
    // initialized once only. All ws reconnection
    // and recovery mechanisms must be handled by
    // the SecWebSocket internally.
    if (dispatcher) {
        logger.warn("Websocket must be initialized only once");
        obeyReconnect();
        return;
    }

    setResponseHandlerLogger(logger);

    initializeInMainThread();

    // we'll dispatch the application info if it is updated
    Agent.eventEmitter.on(Agent.EVENTS.APPLICATION_INFO_UPDATE_EVENT, (applicationInfo) => {
        if (!NRAgent || (NRAgent && applicationInfo.entityGuid)) {
            dispatcher(applicationInfo);
        }
    });
    Agent.eventEmitter.on(Agent.EVENTS.RECONNECT_WS_EVENT, () => {
        setWebSocketConn();
        wsInstance.reconnect();
    });

    setTimeout(() => {
        setInterval(sendHC, HC_INTERVAL_MS);
        sendHC();
        try {
            let apiEndpoints = require('../../../instrumentation-security/core/route-manager').getAllAPIEndPoints();
            let data = require('./apiEndpoints').APIEndPoint(apiEndpoints);
            logger.debug("All API end points of the application is:", JSON.stringify(data));
            getDispatcherAndSendEvent(data);
            require('../core/ExceptionReporting').startExceptionSendingSchedular();
        } catch (error) {
            logger.debug("Error while processing API endpoints", error);
        }

        try {
            const framework = NRAgent.environment.get('Framework')[0];
            const dispatcher = NRAgent.environment.get('Dispatcher')[0];
            const logMessage = new LogMessage.logMessage("INFO", `Detected framework: ${framework} and dispatcher: ${dispatcher}`, __filename, null);
            commonUtils.addLogEventtoBuffer(logMessage);
        } catch (error) {
            logger.debug("Error while extracting data from APM environment", error);
        }
    }, 20000);


    setInterval(commonUtils.logRollOver, 30000);
    initLogger.info("[STEP-5] => Security Agent components started");
};

/**
 * This initiates the ws in main thread
 */
function initializeInMainThread() {
    logger.info(LOG_MESSAGES.NODE_VERSION_MSG, process.version);
    if (!wsInstance) {
        const validatorService = commonUtils.getValidatorServiceEndpointURL();
        wsInstance = new SecWebSocket(validatorService, {}, logger);
        dispatcher = function dispatcher(message) {
            if (Agent.getAgent().status.getStatus() == 'active') {
                wsInstance.dispatch(message);
            }
        };
    } else {
        return wsInstance;
    }
}

function getTestIdentifier() {
    try {
        let authHeaders = require('./Auth-headers').getInstance();
        let testIdentifer = authHeaders['NR-CSEC-IAST-TEST-IDENTIFIER'] ? authHeaders['NR-CSEC-IAST-TEST-IDENTIFIER'] : '';
        return testIdentifer
    } catch (error) {
        logger.debug("unable to get test identifier", error);
    }

}

/**
 * Sends Agent HelthCheck to Validator.
 */
const sendHC = async function () {
    if (AgentStatus.getInstance().getStatus() != AgentStatus.CSECAgentStatus.codes.DISABLED && (NRAgent ? (NRAgent.config.security.enabled && NRAgent.canCollectData()) : true)) {
        let json = hc.getInstance().get();
        json = JSON.parse(json);
        json.policyVersion = applicationInfo.policyVersion;
        json.entityGuid = applicationInfo.entityGuid;
        if (NRAgent && NRAgent.config) {
            json.appEntityGuid = NRAgent.config.entity_guid;
            json.appAccountId = NRAgent.config.account_id;
        }

        try {
            json.stats = await commonUtils.getHCStats();
        } catch (error) {
            logger.error(error);
        }

        json.serviceStatus = {};
        json.serviceStatus.websocket = commonUtils.getWSHealthStatus();
        json.serviceStatus.logWriter = await commonUtils.isLogAccessible(`${LOG_DIR}node-security-collector.log`);
        json.serviceStatus.initLogWriter = await commonUtils.isLogAccessible(`${LOG_DIR}node-security-collector-init.log`);
        json.serviceStatus.agentActiveStat = commonUtils.isAgentActiveState();
        json.serviceStatus.iastRestClient = commonUtils.iastRestClientStatus();

        json.exitEventSentCount = json.exitEventStats.sent;
        json.eventRejectionCount = json.raspEventStats.rejected + json.iastEventStats.rejected;
        json.eventProcessingErrorCount = json.raspEventStats.errorCount + json.iastEventStats.errorCount;
        json.eventSendRejectionCount = json.eventRejectionCount;
        json.eventSendErrorCount = json.eventProcessingErrorCount;

        json.scanStartTime = commonUtils.scanStartTime;
        json.trafficStartedTime = commonUtils.trafficStartedTime;
        json.iastTestIdentifer = getTestIdentifier();

        hc.getInstance().resetDropCount();
        hc.getInstance().resetProcessedCount();
        hc.getInstance().resetEventSentCount();
        hc.getInstance().resetHttpRequestCount();
        hc.getInstance().resetEventStats();


        logger.info('Health Check Status:', JSON.stringify(json));
        getDispatcherAndSendEvent(json);
    }
};

/**
 * Will send event asyncronously.
 *
 * @param {JSON} eventJson
 */
function getDispatcherAndSendEvent(eventJson) {
    if (eventJson) {
        const eventType = eventJson.jsonName;
        if (eventType === JSON_NAME.EVENT || eventType === EXITEVENT) {
            hc.getInstance().registerEventProcessed();
        }

        dispatcher(eventJson);

        if (eventType === JSON_NAME.EVENT || eventType === EXITEVENT) {
            hc.getInstance().registerEventSent();
        }
    }
}

/**
 * Sends passed Event to Validator.
 *
 * @param {Event} event
 * @param {Function} callback (optional)
 */
function sendEvent(event, callback = DEFAULT_EVENT_SEND_CB) {
    dispatcher(event);
    callback();
};


function obeyReconnect() {
    wsInstance.obeyReconnect();
}

function closeWS() {
    wsInstance.closeWS();
}

module.exports = {
    initialize,
    write: sendEvent,
    dispatcher: getDispatcherAndSendEvent,
    obeyReconnect,
    closeWS
};
