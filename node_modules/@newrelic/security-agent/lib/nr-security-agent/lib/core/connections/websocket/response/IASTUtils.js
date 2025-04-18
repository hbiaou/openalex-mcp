/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */
const { Agent } = require('../../../agent');
let pendingRequestIds = new Set();
let completedRequestsMap = new Map();
const PolicyManager = require('../../../Policy');
const API = require('../../../../../../nr-security-api');
let batchSize;
const batchthreshold = 200;
const logs = require('../../../logging');
let logger = logs.getLogger();
const commonUtils = require('../../../commonUtils');

function getPendingRequestIds() {
    return [...pendingRequestIds];
}

function addPendingRequestId(id) {
    pendingRequestIds.add(id);
}

function removeRequestId(id) {
    completedRequestsMap.delete(id);
}

function removePendingRequestId(id) {
    pendingRequestIds.delete(id);
}

// for last leg
function completedRequestsMapInit(id) {
    completedRequestsMap.set(id, []);
}

function addCompletedRequests(id, eventId) {
    let data = completedRequestsMap.get(id);
    if (!data) {
        return;
    }
    data.push(eventId);
    completedRequestsMap.set(id, data);
}

function getCompletedRequestsMap() {
    return completedRequestsMap;
}

function clearCompletedRequestMap() {
    completedRequestsMap.clear();
}

function clearPendingRequestIdSet() {
    pendingRequestIds.clear();
}

function IASTCleanup() {
    clearCompletedRequestMap();
    clearPendingRequestIdSet();
}

function generateIASTDataRequest() {

    const policyInstance = PolicyManager.getInstance();
    if (policyInstance.data && policyInstance.data.vulnerabilityScan && policyInstance.data.vulnerabilityScan.iastScan) {
        batchSize = batchSize ? batchSize : policyInstance.data.vulnerabilityScan.iastScan.probing.batchSize;
        if (batchSize > batchthreshold) {
            batchSize = policyInstance.data.vulnerabilityScan.iastScan.probing.batchSize;
        }
    }
    if (getCompletedRequestsMap().size >= batchSize || batchSize < batchthreshold || getPendingRequestIds().length < batchSize) {
        batchSize = (2 * batchSize) - getPendingRequestIds().length;
    }

    const NRAgent = API.getNRAgent();
    let scanRateLimit = 3600;
    let scanRateLimitFromConfig = parseInt(NRAgent.config.security.scan_controllers.iast_scan_request_rate_limit);
    scanRateLimit = scanRateLimitFromConfig
    if (isNaN(scanRateLimitFromConfig)) {
        scanRateLimit = 3600;
    }
    if (scanRateLimit >= 0 || scanRateLimit < 0) {
        batchSize = parseInt(scanRateLimit / 12);
        if (scanRateLimit < 12) {
            batchSize = 1;
        } else if (scanRateLimit > 3600) {
            batchSize = 300;
        }
    }

    let object = {};
    object['jsonName'] = 'iast-data-request';
    object['applicationUUID'] = Agent.getAgent().applicationInfo.applicationUUID;
    object['appEntityGuid'] = Agent.getAgent().applicationInfo.appEntityGuid;
    object['appAccountId'] = Agent.getAgent().applicationInfo.appAccountId;
    if (batchSize && batchSize > 100) {
        batchSize = 100;
    }
    object["batchSize"] = batchSize ? batchSize : 300;
    object['pendingRequestIds'] = getPendingRequestIds();
    object['completedRequests'] = Object.fromEntries(getCompletedRequestsMap());
    return object;
}


module.exports = {
    getPendingRequestIds,
    addPendingRequestId,
    removePendingRequestId,
    generateIASTDataRequest,

    // for last leg
    addCompletedRequests,
    completedRequestsMapInit,
    getCompletedRequestsMap,
    removeRequestId,
    IASTCleanup



}


