/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const { EventEmitter } = require('events');

const APPLICATION_INFO_UPDATE_EVENT = 'application-info-updated';
const WS_CONNECTION_STATUS_UPDATE_EVENT = 'ws-connection-updated';
const AGENT_STATUS_UPDATED_EVENT = 'agent-status-updated';
const WS_UPDATE_EVENT = 'websocket-updated';
const RECONNECT_WS_EVENT = 'reconnect-websocket';
const LOG_MESSAGES = require('./sec-agent-constants').LOG_MESSAGES;
const LinkingMetaData = require('./LinkingMetadata');
const API = require('../../../nr-security-api');
let NRAgent = API.getNRAgent();
const agentConfig = require('../../resources/config')

const EVENTS = {
    APPLICATION_INFO_UPDATE_EVENT,
    WS_CONNECTION_STATUS_UPDATE_EVENT,
    AGENT_STATUS_UPDATED_EVENT,
    WS_UPDATE_EVENT,
    RECONNECT_WS_EVENT
};

let instance = null;
/**
 * This defines the CSEC agent instance which would hold
 * necessary info for agent.
 *
 * @param {ApplicationInfo} applicationInfo
 * @param {Logger} logger
 * @param {WebSocket} client
 * @param {AgentStatus} status
 */
function Agent(applicationInfo, logger, client, status) {
    const version = require(agentConfig.AGENT_DIR + '/package.json').version;
    this.applicationInfo = applicationInfo;
    this.client = client;
    this.version = version;
    this.logger = logger;
    this.status = status;
    this.wsStatus = 0;
    this.delayed = false;
}

Agent.prototype = {};
Agent.prototype.constructor = Agent;

/**
 * Sets the application info in agent
 * and triggers the update event.
 * @param {ApplicationInfo} applicationInfoObject
 */
Agent.prototype.setApplicationInfo = function setApplicationInfo(applicationInfoObject) {
    this.applicationInfo = applicationInfoObject;
    if (NRAgent && NRAgent.config && NRAgent.config.entity_guid) {
        this.applicationInfo.entityGuid = NRAgent.config.entity_guid;
        this.applicationInfo.identifier.nodeId = NRAgent.config.entity_guid;
        this.applicationInfo.identifier.id = NRAgent.config.entity_guid;

        Agent.eventEmitter.emit(EVENTS.APPLICATION_INFO_UPDATE_EVENT, applicationInfoObject);
        const logs = require('./logging');

    }

};

/**
 * Sets the websocket client in agent
 * and triggers the update event.
 * @param {SecWebSocket} client
 */
Agent.prototype.setClient = function setClient(client) {
    this.client = client;
    Agent.eventEmitter.emit(EVENTS.WS_UPDATE_EVENT, client);
};

/**
 * Sets the websocket status in agent
 * and triggers the update event.
 * @param {ApplicationInfo} applicationInfoObject
 */
Agent.prototype.setWebsocketStatus = function setWebsocketStatus(status) {
    this.wsStatus = status;
    Agent.eventEmitter.emit(EVENTS.WS_CONNECTION_STATUS_UPDATE_EVENT, status);
};

/**
 * Sets the agent status in agent
 * and triggers the update event.
 * @param {ApplicationInfo} applicationInfoObject
 */
Agent.prototype.setAgentStatus = function setAgentStatus(status) {
    this.status = status;
    Agent.eventEmitter.emit(EVENTS.AGENT_STATUS_UPDATED_EVENT, status);
};


Agent.EVENTS = EVENTS;

Agent.eventEmitter = new EventEmitter();

/**
 * This initializes a singleton agent instance.
 *
 * @param {ApplicationInfo} applicationInfo
 * @param {Logger} logger
 * @param {WebSocket} client
 * @param {AgentStatus} status
 */
Agent.init = function init(applicationInfo, logger, client, status) {
    if (!instance) {
        instance = new Agent(applicationInfo, logger, client, status);
    }
};

/**
 * Returns the singleton agent instance.
 * Returns null if init is not called.
 *
 * @returns {Agent} agent
 */
Agent.getAgent = function getAgent() {
    return instance;
};

Agent.setNRAgent = function setNRAgent(agent) {
    if (agent) {
        NRAgent = agent;
    }
    const CSECAgent = Agent.getAgent();
    if (CSECAgent) {
        CSECAgent.applicationInfo.appEntityGuid = NRAgent.config.entity_guid;
        CSECAgent.applicationInfo.appAccountId = NRAgent.config.account_id;
        CSECAgent.applicationInfo.linkingMetadata = LinkingMetaData.getLinkingMetadata();
        CSECAgent.applicationInfo.linkingMetadata.agentRunId = NRAgent.config.run_id;
        CSECAgent.setApplicationInfo(CSECAgent.applicationInfo);
    }
};


module.exports = {
    Agent
};
