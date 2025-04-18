/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const requestMap = new Map();
const API = require("../../nr-security-api");
const NRAgent = API.getNRAgent();
const logger = API.getLogger();
const regexPatterns = NRAgent && NRAgent.config.security.exclude_from_iast_scan.api

/**
 * Utility to get request by transaction Id
 * @param {*} id 
 * @returns 
 */
function getRequestFromId(id) {
    return requestMap.get(id);
}

/**
 * Utility function to set request data corresponding to transacation Id
 * @param {*} id 
 * @param {*} requestData 
 */
function setRequest(id, requestData) {

    requestMap.set(id, requestData);
    try {
        const stringToMatch = requestData.url;
        // const filteredString = stringToMatch.split('?')[0];
        const filteredString = stringToMatch;
        let isRegexMatchestoURL = false;
        for (let index = 0; index < regexPatterns.length; index++) {
            const regex = new RegExp(regexPatterns[index], 'gm');
            const matchResult = filteredString.match(regex);
            if (matchResult && matchResult.length > 0) {
                const data = matchResult[0];
                if (filteredString === data) {
                    isRegexMatchestoURL = true;
                }
            }
        }
        if (isRegexMatchestoURL) {
            requestMap.delete(id);
            if (API.getSecAgent().status.getStatus() !== 'disabled') {
                logger.debug("Excluding URL %s from IAST processing due to ignore API setting", filteredString);
            }
        }
    } catch (error) {
        logger.debug("Error while processing API regex for restriction", error);
    }

}

/**
 * Utility to get request using shim
 * @param {*} shim 
 * @returns 
 */
function getRequest(shim) {
    const transaction = shim.tracer.getTransaction();
    if (transaction) {
        const transactionId = transaction.id;
        return getRequestFromId(transactionId);
    }
    else if (shim.agent.getLinkingMetadata()) {
        let linkingMetadata = shim.agent.getLinkingMetadata();
        if (linkingMetadata['trace.id']) {
            let traceId = linkingMetadata['trace.id'];
            return getRequestFromId(traceId);
        }
    }
}

/**
 * Utility to update request body
 * @param {*} shim 
 * @param {*} data 
 */
function updateRequestBody(shim, data, isTruncated) {
    const transaction = shim.tracer.getTransaction(); 
    if (transaction) {
        const transactionId = transaction.id;
        const requestData = getRequestFromId(transactionId);
        if (requestData) {
            requestData.body = data;
            requestData.dataTruncated = isTruncated;
            setRequest(transactionId, requestData);
        }
    }
    if (shim.agent.getLinkingMetadata()) {
        let linkingMetadata = shim.agent.getLinkingMetadata();
        if (linkingMetadata['trace.id']) {
            let traceId = linkingMetadata['trace.id'];
            const requestData = getRequestFromId(traceId);
            if (requestData) {
                requestData.body = data;
                requestData.dataTruncated = isTruncated;
                setRequest(traceId, requestData)
            }
        }
    }
}

/**
 * Utility to clear data based on transaction Id 
 * @param {*} transactionId 
 */
function gcRequestMap(transaction) {
    let transactionId = transaction.id;
    let traceId = transaction._traceId;
    if (requestMap.has(transactionId)) {
        requestMap.delete(transactionId);
    }
    if (requestMap.has(traceId)) {
        requestMap.delete(traceId);
    }
}

module.exports = {
    getRequestFromId,
    getRequest,
    setRequest,
    updateRequestBody,
    gcRequestMap,
    requestMap
}
