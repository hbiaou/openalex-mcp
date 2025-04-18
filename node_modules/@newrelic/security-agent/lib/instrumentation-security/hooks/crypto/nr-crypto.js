/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier:  New Relic Software License v1.0
 */

module.exports = initialize
const requestManager = require('../../core/request-manager');
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');
const logger = API.getLogger();
const NRLIB = 'newrelic/lib';
const SALIB = 'security-agent/lib'

/**
 * Entry point of crypto module hook
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName) {
    if (API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.insecure_settings) {
        logger.warn('insecure_settings detection is disabled');
        return;
    }
    logger.info('Instrumenting ' + moduleName)
    cryptoCipherHooks(shim, mod, 'createCipheriv', moduleName);
    cryptoHashHmacHooks(shim, mod, 'createHash', moduleName);
    cryptoHashHmacHooks(shim, mod, 'createHmac', moduleName);
    cryptoRandomHooks(shim, Math, 'random', "Math");
}
/**
 * wrapper to hook crypto cipher methods
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 * @param {*} moduleName 
 */
function cryptoCipherHooks(shim, mod, methodName, moduleName) {
    shim.wrap(mod, methodName, function makeWrapper(shim, fn) {
        logger.debug(`Instrumenting ${moduleName}.${methodName}`);
        return function wrapper() {
            const interceptedArgs = [arguments[0]];
            shim.interceptedArgs = interceptedArgs;
            const request = requestManager.getRequest(shim);
            if (request && API.getSecAgent() && API.getSecAgent().status && API.getSecAgent().status.getStatus() === 'active') {
                const traceObject = secUtils.getTraceObject(shim);
                const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.CRYPTO, EVENT_CATEGORY.CIPHER)
                if (secMetadata.traceObject && secMetadata.traceObject.stacktrace && (secMetadata.traceObject.stacktrace[0].includes(NRLIB) || secMetadata.traceObject.stacktrace[0].includes(SALIB))) {
                    //do nothing
                }
                else {
                    const secEvent = API.generateSecEvent(secMetadata);
                    this.secEvent = secEvent;
                    API.sendEvent(secEvent);
                }
            }
            const result = fn.apply(this, arguments);

            if (result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
                API.generateExitEvent(this.secEvent);
                delete this.secEvent
            }
            return result;
        }
    })
}


/**
 * wrapper to hook crypto hash and mac methods
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 * @param {*} moduleName 
 */
function cryptoHashHmacHooks(shim, mod, methodName, moduleName) {
    shim.wrap(mod, methodName, function makeWrapper(shim, fn) {
        logger.debug(`Instrumenting ${moduleName}.${methodName}`);
        return function wrapper() {
            const interceptedArgs = [arguments[0]];
            shim.interceptedArgs = interceptedArgs;
            const request = requestManager.getRequest(shim);

            if (request && arguments[0] !== 'sha256' && API.getSecAgent() && API.getSecAgent().status && API.getSecAgent().status.getStatus() === 'active') {
                const traceObject = secUtils.getTraceObject(shim);
                const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.HASH, EVENT_CATEGORY.HASH)
                if (secMetadata.traceObject && secMetadata.traceObject.stacktrace && (secMetadata.traceObject.stacktrace[0].includes(NRLIB) || secMetadata.traceObject.stacktrace[0].includes(SALIB))) {
                    //do nothing
                }
                else {
                    const secEvent = API.generateSecEvent(secMetadata);
                    this.secEvent = secEvent;
                    API.sendEvent(secEvent);
                }
            }
            const result = fn.apply(this, arguments);
            if (result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID] && arguments[0] !== 'sha256') {
                API.generateExitEvent(this.secEvent);
                delete this.secEvent
            }
            return result;
        }
    })
}
/**
 * Wrapper for random hooks
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 * @param {*} moduleName 
 */
function cryptoRandomHooks(shim, mod, methodName, moduleName) {
    shim.wrap(mod, methodName, function makeWrapper(shim, fn) {
        logger.debug(`Instrumenting ${moduleName}.${methodName}`);
        return function wrapper() {
            const interceptedArgs = ["Math.random"];
            shim.interceptedArgs = interceptedArgs;
            const request = requestManager.getRequest(shim);
            if (request && API.getSecAgent() && API.getSecAgent().status && API.getSecAgent().status.getStatus() === 'active') {
                const traceObject = secUtils.getTraceObject(shim);
                const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.RANDOM, EVENT_CATEGORY.WEAKRANDOM)
                if (secMetadata.traceObject && secMetadata.traceObject.stacktrace && secMetadata.traceObject.stacktrace[0] && (secMetadata.traceObject.stacktrace[0].includes(NRLIB) || secMetadata.traceObject.stacktrace[0].includes(SALIB))) {
                    //do nothing
                }
                else {
                    const secEvent = API.generateSecEvent(secMetadata);
                    this.secEvent = secEvent;
                    API.sendEvent(secEvent);
                }

            }
            const result = fn.apply(this, arguments);
            if (result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
                API.generateExitEvent(this.secEvent);
                delete this.secEvent
            }
            return result;
        }
    })
}


