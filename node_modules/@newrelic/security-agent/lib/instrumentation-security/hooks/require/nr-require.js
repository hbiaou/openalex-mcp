/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const requestManager = require('../../core/request-manager');
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { STRING } = require('../../core/constants')
const logger = API.getLogger();
const Module = require('module');
const refDirRegEx = /^(\.\/)|^(\.\.\/)/g;
const path = require('path');
const CSEC = 'nr-security-agent';
const FN_INSPECT = '@contrast/fn-inspect';
const NEWRELIC = 'newrelic';

/**
 * Entry point for require module hook
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim) {

    const original_load = Module._load;
    logger.info('Instrumenting Module._load');

    Module._load = function (request, parent) {

        let moduleName = arguments[0];

        if (arguments[0].match(refDirRegEx) && arguments[1] && arguments[1].path) {
            moduleName = path.resolve(arguments[1].path, arguments[0]);
        }
        
        let flag = false;
        if (moduleName && typeof (moduleName) === STRING && !moduleName.includes(CSEC) && !moduleName.includes(FN_INSPECT)) {
            flag = true;
        }
        else if (parent && parent.id && typeof (parent.id) === STRING && moduleName.includes(CSEC) && parent.id.includes(CSEC) && moduleName.includes(FN_INSPECT)) {
            flag = false;
        }
        else if (parent && parent.id && moduleName && typeof (moduleName) === STRING && moduleName.includes(CSEC) && parent.id.includes(CSEC) && moduleName.includes(FN_INSPECT)) {
            flag = false;
        }

        if ((parent && parent.id && typeof (parent.id) === STRING && parent.id.includes(NEWRELIC)) ||  moduleName.includes(NEWRELIC)){
            flag = false;
        }

        if (flag) {
            requireHook(shim, moduleName, parent);
        }

        return original_load.apply(this, arguments);

    }

}

function requireHook(shim, moduleName, parent) {
    try {
        let request = requestManager.getRequest(shim);
        let fallback = false;
        if (!request) {
            fallback = true;
            let values = [...requestManager.requestMap.values()];
            if (values.length > 0) {
                request = values[values.length - 1];
            }
        }
        if (request) {
            let resolvedModulePath  = require.resolve(moduleName)
            const interceptedArgs = [resolvedModulePath];
            let traceObject;
            if (!fallback) {
                traceObject = secUtils.getTraceObject(shim);
            }
            else {
                traceObject = secUtils.getTraceObjectFallback(request);
            }
            const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.FILE_OPERATION, EVENT_CATEGORY.FILE)
            const secEvent = API.generateSecEvent(secMetadata);
            API.sendEvent(secEvent);
        }
    } catch (error) {
       
    }



}


module.exports = {
    initialize
}

