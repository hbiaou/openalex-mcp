/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const WebSocket = require('ws');
const RingBuffer = require('ringbufferjs');
const stringify = require('fast-safe-stringify');
const { EventEmitter } = require('events');
const API = require('../../../../../nr-security-api');
const NRAgent = API.getNRAgent();
const { Agent } = require('../../agent');
const logs = require('../../logging');
const hc = require('../../health-check');
const fs = require('fs');
const { promisify } = require('../../sec-util');
const ResponseHandler = require('./response');
const { EMPTY_APPLICATION_UUID, LOG_MESSAGES, CSEC_SEP, NR_CSEC_FUZZ_REQUEST_ID, EXITEVENT, JSON_NAME, SEVERE } = require('../../sec-agent-constants');
const commonUtils = require('../../commonUtils');
const IASTUtil = require('../websocket/response/IASTUtils');
const LogMessage = require('../../LogMessage');
const proxyUtil = require('./proxy-util');

const BUSY = 'busy';
const IDLE = 'idle';
const CONNECTING = 'connecting';
const WS_ON_OPEN = 'open';
const WS_ON_MSG = 'message';
const WS_ON_ERR = 'error';
const WS_ON_PONG = 'pong';
const ACK = 'ACK';
const INIT_PING_RETRY_DELAY_ON_FAIL = 200; // in ms
const RECONNECTION_DELAY = 500; // ms
const APPLICATION_INFO_JSON_NAME = 'applicationinfo';
let APP_INFO;
let CSEC_WS_STATE = '';

const queue = new RingBuffer(10);
let logger = logs.getLogger();
const initLogger = logs.getInitLogger();
let webSocket;
let pingIntervalConst;
let initTimeOut;
let lastPongtime;

/**
 * defines the WebSocket callbacks object
 *
 * @param {Function} onOpen
 * @param {Function} onMessage
 * @param {Function} onError
 */
function WSCallbacks(onOpen, onMessage, onError) {
    this.onOpen = onOpen;
    this.onMessage = onMessage;
    this.onError = onError;
}




/**
 * This defines the websocket and related
 * methods
 *
 * @param {String} uri - to connect to
 * @param {WSCallbacks} callbacks - on open, on message and on error callbacks
 */
function SecWebSocket(uri, callbacks = {}, logr = null) {
    this.instance = undefined;
    this.isICReadyForEvents = false;
    this.uri = uri;
    this.event = new EventEmitter();
    this.openCB = (callbacks.onOpen || defaultOnOpenCB()).bind(this);
    this.msgCB = (callbacks.onMessage || defaultOnMsgCB()).bind(this);
    this.errCB = (callbacks.onError || defaultOnErrCB()).bind(this);
    logger = logr || logger;
    this.wsRetryCount = 0;
    this.init();
}

SecWebSocket.prototype = {};
SecWebSocket.prototype.constructor = SecWebSocket;


/**
 * Initiates a new web socket connection.
 */
SecWebSocket.prototype.init = function init() {
    if (webSocket) {
        try {
            webSocket.removeAllListeners('open');
            webSocket.removeAllListeners('close');
            webSocket.removeAllListeners('message');
            webSocket.terminate();
        } catch (error) {
            logger.debug("Error while terminating webSocket instance", error);
        }
    }
    setWebSocketConn();
    this.setValidatorNotReadyForEvents();
    const validatorService = commonUtils.getValidatorServiceEndpointURL();
    const authHeaders = require('../../Auth-headers').getInstance();
    initLogger.info(`Connecting to Validator at ${validatorService}`);
    IASTUtil.IASTCleanup();
    let cert = '';
    try {
        const certPath = commonUtils.getPathOfCACert();
        cert = fs.readFileSync(certPath, 'utf8');
    } catch (error) {
        logger.error("Error in reading certificate:", error);
        commonUtils.sendErrorToErrorInbox(error)
        const logMessage = new LogMessage.logMessage(SEVERE, 'Error in reading certificate for websocket', __filename, error);
        commonUtils.addLogEventtoBuffer(logMessage);

    }
    const isProxy = !!(NRAgent.config.proxy || NRAgent.config.proxy_port || NRAgent.config.proxy_host)
    if(isProxy){
        const agentWithProxy = proxyUtil.proxyAgent(NRAgent.config);
        webSocket = new WebSocket(validatorService, { headers: authHeaders, cert: cert, handshakeTimeout: 10000, agent:agentWithProxy });
    }
    else{
        webSocket = new WebSocket(validatorService, { headers: authHeaders, cert: cert, handshakeTimeout: 10000 });
    }

    webSocket.on(WS_ON_OPEN, this.openCB);
    webSocket.on(WS_ON_MSG, this.msgCB);
    webSocket.on(WS_ON_ERR, this.errCB);
    webSocket.on(WS_ON_PONG, () => {
        lastPongtime = Date.now();
        commonUtils.setWSHealthStatus('OK');
        logger.debug("Pong received from Validator");

        try {
            let logBuffer = commonUtils.getLogEvents();
            while (logBuffer.size() > 0) {
                let logEvent = logBuffer.deq();
                this.dispatch(logEvent);
            }
        } catch (error) {
            logger.error("Error while sending log events", error);
        }

    })
    webSocket.on('close', () => {
        logger.warn("WS connection closed");
        this.obeyReconnect();
    })
    this.instance = webSocket;
};

/**
 * Re-initiates the websocket by disconnecting
 * and initiating a new websoc connection.
 */
SecWebSocket.prototype.reconnect = function reconnect() {
    const { instance } = this;
    if (instance.readyState === WebSocket.CONNECTING &&
        CSEC_WS_STATE === CONNECTING) {
        return;
    }
    setWebSocketConn();
    this.setValidatorNotReadyForEvents();

    if (instance.readyState === WebSocket.OPEN) {
        this.openCB();
        return;
    }
    commonUtils.setWSHealthStatus('Error');
    commonUtils.sendErrorToErrorInbox(new Error("Unable to connect to Security Engine"))
    logger.debug(LOG_MESSAGES.DETECTED_BROKEN_CONN);
    this.obeyReconnect();

};

SecWebSocket.prototype.obeyReconnect = function obeyReconnect() {
    if (Agent.getAgent().status.getStatus() == 'disabled') {
        return;
    }
    const { instance } = this;
    if (initTimeOut) {
        clearTimeout(initTimeOut);
    }

    initTimeOut = setTimeout(() => {

        logger.debug("Terminating ws instance and reconnecting");
        try {
            instance.terminate();
        } catch (err) {
            logger.debug("Error while terminating ws instance");
        }
        this.init();
    }, (5 + (Math.floor(Math.random() * 11))) * 1000)

}

SecWebSocket.prototype.closeWS = function closeWS() {
    const { instance } = this;
    try {
        instance.close();
    } catch (error) {
        logger.error("Error while closing websocket", error);
    }
}

SecWebSocket.prototype.pingWS = async function pingWS() {
    if (Agent.getAgent().status.getStatus() != 'active') {
        return;
    }
    const self = this;
    let currentTime = Date.now();

    let timeDiffInPing = (currentTime - lastPongtime) / 1000;
    logger.debug("Websocket ready state is:", self.instance.readyState)

    if (timeDiffInPing > 40 && lastPongtime != 0 && self.instance.readyState > 1) {
        self.obeyReconnect();
        lastPongtime = 0;
        return;
    }

    try {
        await promisify(self.instance, self.instance.ping)(ACK, true, function (err) {
            if (err) {
                logger.debug("Error while pinging:", err);
                commonUtils.setWSHealthStatus('Error');
    
            }
        });
    } catch (err) {
        logger.debug("error in ping:", err);
        commonUtils.setWSHealthStatus('Error');
        return;
    }

}

/**
 * sends the event over the websocket instance.
 * @param {JSON} event
 */
SecWebSocket.prototype.dispatch = async function dispatch(event) {
    if (event.jsonName === APPLICATION_INFO_JSON_NAME) {
        APP_INFO = event;
    }
    if (event.parentId && event.httpRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        try {
            let apiId = event.httpRequest.headers[NR_CSEC_FUZZ_REQUEST_ID].split(CSEC_SEP)[0]
            if (apiId == event.apiId) {
                IASTUtil.addCompletedRequests(event.parentId, event.id);
            }
        } catch (error) {
            logger.debug("Error while mapping completedRequests:", error);
        }

    }

    RegExp.prototype.toJSON = RegExp.prototype.toString;
    const eventStr = stringify(event);
    if (!this.instance ||
        this.instance.readyState !== WebSocket.OPEN ||
        !this.isICReadyForEvents
    ) {
        handleDispatchFailure(this, event, eventStr);
        return;
    }
    try {
        await promisify(this.instance, this.instance.send)(eventStr, { mask: true }, () => {
            logger.debug(LOG_MESSAGES.EVENT_SENT + eventStr);
            if (event.jsonName == JSON_NAME.EVENT) {

                if (event.httpRequest && event.httpRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
                    hc.getInstance().iastEventStats.sent++;
                }
                else {
                    hc.getInstance().raspEventStats.sent++;
                }

            }
            if (event.jsonName == EXITEVENT) {
                hc.getInstance().exitEventStats.sent++;
            }

        })
    } catch (error) {
        logger.debug(LOG_MESSAGES.ERROR_WHILE_SEND_EVENT, eventStr, error);
        handleDispatchFailure(this, event, eventStr);
    }
};

/**
 * sends the applicationInfor over the websocket instance.
 * @param {JSON} applicationInfoJSON
 */
SecWebSocket.prototype.dispatchApplicationInfo = async function dispatchApplicationInfo(applicationInfoJSON) {
    const eventStr = stringify(applicationInfoJSON);
    if (applicationInfoJSON.applicationUUID === EMPTY_APPLICATION_UUID) {
        throw new Error('ApplicationInfo not completely Initialized, No application identification detail found!');
    }
    if (this.instance.readyState !== WebSocket.OPEN) {
        logger.warn('Tried to send ApplicationInfo when socket was not open');
    }
    try {
        await promisify(this.instance, this.instance.send)(eventStr, { mask: true });
    } catch (error) {
        logger.warn('Error while sending applicationInfo:', error);
        this.obeyReconnect();
    }
};



/**
 * this sets the isICReadyForEvents property
 */
SecWebSocket.prototype.setICReadyForEvents = function setICReadyForEvents() {
    this.isICReadyForEvents = true;
};

/**
 * this unsets the isICReadyForEvents property
 */
SecWebSocket.prototype.setValidatorNotReadyForEvents = function setValidatorNotReadyForEvents() {
    this.isICReadyForEvents = false;
};

/**
 * This would flush all the events out of
 * event queue and publish to IC.
 *
 * If the send fails there is no way to
 * recover these events.
 */
SecWebSocket.prototype.flushEventQueue = async function flushEventQueue() {
    try {
        const sentEvents = [];
        for (let counter = 0; counter < queue.size(); counter += 1) {
            hc.getInstance().registerEventProcessed();
            sentEvents.push(promisify(this.instance, this.instance.send)(queue.deq(), { mask: true }));
        }
        const results = await Promise.all(sentEvents);
        hc.getInstance().registerEventsSent(results.length);
    } catch (err) {
        logger.debug('Flush failed, reception of all events on IC couldn\'t be ensured.');
    }
};

/**
 * this handles the event dispatch failure
 *
 * @param {SecWebSocket} self
 * @param {String} eventStr
 */
const handleDispatchFailure = (self, event, eventStr) => {
    // we would want to drop applicationinfo events as the latest
    // applicationinfo would anyway be relayed on reconnection
    // so feeding an old applicationinfo JSON would be incorrect
    if (eventStr && event.jsonName !== APPLICATION_INFO_JSON_NAME) {
        hc.getInstance().registerEventDrop();
        if (event.httpRequest && event.httpRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
            hc.getInstance().iastEventStats.errorCount++;
        }
        else {
            hc.getInstance().raspEventStats.errorCount++;
        }

    }
};

/**
 * This is the websocket on open default listener
 * generator.
 *
 * If we fail to ping the ws server, we
 * will retry sending the init ping after a
 * defined delay.
 * Otherwise if the ping is successful we will
 * dispatch the application info.
 *
 * @param {SecWebSocket} self
 */
const defaultOnOpenCB = () => async function onOpen() {
    const self = this;
    lastPongtime = 0;

    if (pingIntervalConst) {
        clearInterval(pingIntervalConst);
    }
    pingIntervalConst = setInterval(() => {
        self.pingWS();
    }, 30000)

    if (self.isICReadyForEvents) {
        return;
    }
    if (self.instance.readyState !== WebSocket.OPEN) {
        self.reconnect();
        return;
    }

    const validatorService = commonUtils.getValidatorServiceEndpointURL();
    initLogger.info(`[STEP-4] => Web socket connection to SaaS validator established successfully at ${validatorService}`)
    try {

        this.wsRetryCount = 0;
        commonUtils.setWSHealthStatus('OK')
        Agent.getAgent().status.setStatus('active');
        const applicationInfo = APP_INFO || Agent.getAgent().applicationInfo;
        await self.dispatchApplicationInfo(applicationInfo);

        self.setICReadyForEvents();
        ResponseHandler.FuzzRequestHandler.setLastFuzzEventTime();
        initLogger.info(LOG_MESSAGES.SENDING_APPINFO_COMPLETE, JSON.stringify(applicationInfo));
    } catch (err) {
        logger.error(`Connection broken: ${err.message}`);
        commonUtils.sendErrorToErrorInbox(err);
        commonUtils.setWSHealthStatus('Error')
        setWebSocketConn();
        self.setValidatorNotReadyForEvents();
        setTimeout(self.openCB, INIT_PING_RETRY_DELAY_ON_FAIL);
    }
};

/**
 * This is the websocket on error default listener
 * generator.
 *
 * This will close and re-establish the websocket
 * connection once if invoked.
 *
 * @param {SecWebSocket} self
 */
const defaultOnMsgCB = () => function onMessage(data) {
    const json = JSON.parse(data);
    ResponseHandler.handle(json);
};

/**
 * This is the websocket on error default listener
 * generator.
 *
 * This will close and re-establish the websocket
 * connection once if invoked.
 *
 * @param {SecWebSocket} self
 */
const defaultOnErrCB = () => function onClose(error) {
    commonUtils.setWSHealthStatus('Error');
    const self = this;
    logger.error("Error while connecting to validator:", error.message)
    const logMessage = new LogMessage.logMessage(SEVERE, 'Error while connecting to validator', __filename, error);
    commonUtils.sendErrorToErrorInbox(error);
    commonUtils.addLogEventtoBuffer(logMessage);
    logger.warn("Security Agent INACTIVE!!!")
    if (error && error.code && (error.code === 'ECONNREFUSED' || error.code === 'EPIPE' || error.code === 'ECONNRESET')) {
        logger.debug("WS Client Error callback called:", error);
        self.obeyReconnect();
    }
    else {
        self.reconnect();
    }
};

SecWebSocket.Events = {
    BUSY,
    IDLE,
    CONNECTING
};

SecWebSocket.States = {
    BUSY,
    IDLE,
    CONNECTING
};
SecWebSocket.PING_MSG = ACK;
SecWebSocket.PING_RETRY_INTERVAL = INIT_PING_RETRY_DELAY_ON_FAIL;
SecWebSocket.RECONNECTION_DELAY = RECONNECTION_DELAY;


/**
 * Sets the websocket state as connecting
 */
function setWebSocketConn() {
    CSEC_WS_STATE = CONNECTING;
}


module.exports = {
    WSCallbacks,
    SecWebSocket,
    setWebSocketConn
};
