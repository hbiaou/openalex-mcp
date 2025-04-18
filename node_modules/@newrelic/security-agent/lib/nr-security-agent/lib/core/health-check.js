/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const { Agent } = require('./agent');
const { JSON_NAME } = require('./sec-agent-constants');
const { BasicInfo } = require('./event');
const EventStats = require('./event-stats');

const NODE_JS_LITERAL = 'Node.js:';

let NODE_SERVER;
let instance;
const logs = require('./logging');
let logger = logs.getLogger();
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();

/**
 * Retruns an instance of HC.
 * Creates one if not already created.
 *
 * @returns {HC} instance
 */
module.exports.getInstance = function () {
    const agent = Agent.getAgent();
    if (!instance) {
        if (agent && !NODE_SERVER) {
            NODE_SERVER = NODE_JS_LITERAL + agent.applicationInfo.binaryVersion;
        }
        instance = new HC(agent.applicationInfo);
    }
    return instance;
};


/**
 * Creates a new HealthCheck object.
 *
 * @param {ApplicationInfo} info
 */
function HC(info) {
    BasicInfo.call(this);

    this.applicationUUID = info.applicationUUID;
    this.eventType = 'sec_health_check_lc';
    if (NRAgent && NRAgent.config) {
        this.appEntityGuid = NRAgent.config.entity_guid;
        this.appAccountId = NRAgent.config.account_id;
    }
    this.protectedServer = NODE_SERVER;
    this.eventDropCount = 0;
    this.eventProcessed = 0;
    this.eventSentCount = 0;
    this.httpRequestCount = 0;
    this.isHost = info.identifier.isHost;
    this.collectorVersion = info.collectorVersion;
    this.jsonVersion = info.jsonVersion;
    this.buildNumber = info.buildNumber;
    this.jsonName = JSON_NAME.HC;
    this.pid = info.pid;
    this.iastEventStats = EventStats.getInstance();
    this.raspEventStats = EventStats.getInstance();
    this.exitEventStats = EventStats.getInstance();
    this.scanStartTime =  require('./commonUtils').scanStartTime;
    this.trafficStartedTime = require('./commonUtils').trafficStartedTime;
    this.procStartTime = Date.now() - Math.floor(process.uptime() * 1000);


    /**
     * registers an event drop.
     */
    this.registerEventDrop = function () {
        this.eventDropCount++;
    };

    /**
     * mark application to be running on host.
     */
    this.markHost = function () {
        this.isHost = true;
    };

    /**
     * resets the drop count.
     */
    this.resetDropCount = function () {
        this.eventDropCount = 0;
    };

    /**
     * registers a processed event.
     */
    this.registerEventProcessed = function () {
        this.eventProcessed++;
    };

    /**
     * registers a processed event.
     */
    this.registerEventSent = function () {
        this.eventSentCount++;
    };

    /**
     * registers n processed event.
     */
    this.registerEventsSent = function (n) {
        this.eventSentCount += n;
    };
    /**
     * resets the processed count.
     */
    this.resetProcessedCount = function () {
        this.eventProcessed = 0;
    };

    /**
     * resets the Event sent count.
     */
    this.resetEventSentCount = function () {
        this.eventSentCount = 0;
    };

    /**
     * registers a http request count
     */
    this.registerHttpRequestCount = function () {
        this.httpRequestCount++;
    };

    /**
     * resets the Event sent count.
     */
    this.resetHttpRequestCount = function () {
        this.httpRequestCount = 0;
    };

    /**
     * resets the IAST EventStats.
     */
    this.resetIASTEventStats = function () {
        this.iastEventStats.processed = 0;
        this.iastEventStats.sent = 0;
        this.iastEventStats.rejected = 0;
        this.iastEventStats.errorCount = 0;
    };

    /**
    * resets the RASP EventStats.
    */
    this.resetRASPEventStats = function () {
        this.raspEventStats.processed = 0;
        this.raspEventStats.sent = 0;
        this.raspEventStats.rejected = 0;
        this.raspEventStats.errorCount = 0;
    };

    /**
     * resets the EXIT EventStats.
     */
    this.resetEXITEventStats = function () {
        this.exitEventStats.processed = 0;
        this.exitEventStats.sent = 0;
        this.exitEventStats.rejected = 0;
        this.exitEventStats.errorCount = 0;
    };

    /**
    * resets the EventStats.
    */
    this.resetEventStats = function () {
        this.resetIASTEventStats();
        this.resetRASPEventStats();
        this.resetEXITEventStats();
    };


    /**
     * sets gerate hc timestamp.
     */
    this.registerGenerateTime = function () {
        this.timestamp = Date.now();
    };

    this.get = function () {
        this.registerGenerateTime();
        return JSON.stringify(this);
    };
}

HC.prototype = Object.create(BasicInfo.prototype);
HC.prototype.constructor = HC;


/**
 * Sets the logger instance.
 *
 * @param {*} loggerInstance
 */
module.exports.setLogger = loggerInstance => {
    logger = loggerInstance;
};

