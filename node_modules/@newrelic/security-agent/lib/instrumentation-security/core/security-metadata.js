/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

/**
 * Method to create securityMetadata object
 * @param {*} request 
 * @param {*} interceptedArgs 
 * @param {*} traceObject 
 * @param {*} executionId 
 * @param {*} eventType 
 * @param {*} eventCategory 
 * @returns 
 */
function getSecurityMetaData(request, interceptedArgs, traceObject, executionId, eventType, eventCategory) {
    const securityMetadata = {};
    const rHeaders = request.headers;
    try {
        Object.keys(rHeaders).forEach(key => {
            if (rHeaders[key]) {
                rHeaders[key] = String(rHeaders[key]);
            }
        });
    } catch (error) {
    }
    request.headers = rHeaders;
    const httpRequest = Object.assign({}, request);
    if (httpRequest.tempFiles) {
        delete httpRequest.tempFiles;
    }
    securityMetadata.request = httpRequest
    securityMetadata.interceptedArgs = interceptedArgs;
    securityMetadata.traceObject = traceObject
    securityMetadata.executionId = executionId
    securityMetadata.eventType = eventType
    securityMetadata.eventCategory = eventCategory
    return securityMetadata;

}

module.exports = {
    getSecurityMetaData
}