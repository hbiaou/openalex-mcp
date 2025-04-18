/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const LinkingMetaData = require('./LinkingMetadata');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();
const { BasicInfo } = require('./event');
const applicationInfo = require('./applicationinfo').getInstance();
const exceptionsMap = new Map();
const logs = require('./logging');
const logger = logs.getLogger();
const exceptionReportingInterval = 30000;
const http = require('http');
const shaUtil = require('./sha-size-util');

const NR_LIB = '/newrelic/lib';

const GRPCStatusMap = {
    0: 'OK',
    1: 'CANCELLED',
    2: 'UNKNOWN',
    3: 'INVALID_ARGUMENT',
    4: 'DEADLINE_EXCEEDED',
    5: 'NOT_FOUND',
    6: 'ALREADY_EXISTS',
    7: 'PERMISSION_DENIED',
    8: 'RESOURCE_EXHAUSTED',
    9: 'FAILED_PRECONDITION',
    10: 'ABORTED',
    11: 'OUT_OF_RANGE',
    12: 'UNIMPLEMENTED',
    13: 'INTERNAL',
    14: 'UNAVAILABLE',
    15: 'DATA_LOSS',
    16: 'UNAUTHENTICATED',
}

/**
 * constructor function to create createException object
 * @param {*} message
 * @param {*} cause
 * @param {*} stacktrace
 */
function createException(exception) {
    let exceptionObject = {};
    try {
        exceptionObject.message = exception.message ? exception.message : '';
        exceptionObject.cause = null;
        exceptionObject.type = exception.name ? exception.name : 'Error';
        if (exception.stack) {
            let stacktraceInList = exception.stack.split('\n');
            stacktraceInList = stacktraceInList.slice(1);
            let fileteredStackTrace = [];
            for (const str of stacktraceInList) {
                if (!str.includes(NR_LIB) && str.length > 0) {
                    fileteredStackTrace.push(str.trim());
                }
            }
            exceptionObject.stackTrace = fileteredStackTrace;
        }

    } catch (error) {
    }

    return exceptionObject;
}

/**
  * constructor function to create exceptionReporting object;
  * @param {*} timestamp
  * @param {*} level
  * @param {*} message
  * @param {*} caller
  * @param {*} exception
  * @param {*} linkingMetadata
  */
function exceptionReporting(exception, request, responseCode) {
    try {
        BasicInfo.call(this);
        this.jsonVersion = applicationInfo.jsonVersion;
        this.pid = applicationInfo.pid ? applicationInfo.pid : null;
        this.jsonName = 'application-runtime-error';
        this.applicationUUID = applicationInfo.applicationUUID;
        this.policyVersion = applicationInfo.policyVersion;
        this.collectorVersion = applicationInfo.collectorVersion ? applicationInfo.collectorVersion : null;
        this.buildNumber = applicationInfo.buildNumber ? applicationInfo.buildNumber : null;
        this.timestamp = Date.now();
        this.httpRequest = request;
        this.httpRequest.route = request.uri ? request.uri : request.url;
        this.httpRequest.requestURI = request.url.split('?')[0];
        this.exception = null;
        this.counter = 1;
        this.responseCode = responseCode ? responseCode : null

        if (exception) {
            this.exception = createException(exception);
            this.category = exception.name;
            this.traceId = shaUtil.getSHA256ForData(this.exception.stackTrace.join('|') + this.category + this.httpRequest.route + this.httpRequest.method);
        }
        
        if (responseCode) {
            if (responseCode >= 500) {
                this.category = http.STATUS_CODES[responseCode];
                this.traceId = shaUtil.getSHA256ForData(this.category + this.httpRequest.route + this.httpRequest.method);
            }
            else {
                this.category = GRPCStatusMap[responseCode];
                this.traceId = shaUtil.getSHA256ForData(this.category + this.httpRequest.route + this.httpRequest.method);
            }
        }

        if (NRAgent) {
            this.linkingMetadata = LinkingMetaData.getLinkingMetadata();
        }
    } catch (error) {
        logger.debug("Error while generating exceptionReporing", error);
    }

}

function generateExceptionReportingEvent(error, request) {
    try {
        const exception = new exceptionReporting(error, request);
        if(!exception.traceId){
            return;
        }
        let key = exception.exception.type + exception.exception.stackTrace[0];
        if (!exceptionsMap.has(key)) {
            exceptionsMap.set(key, exception);
        }
        else {
            let previousCounter = exceptionsMap.get(key).counter;
            exception.counter = previousCounter ? previousCounter + 1: exception.counter + 1;
            exceptionsMap.set(key, exception);
        }
    } catch (err) {
        logger.debug("Error while generating application-runtime-error:", err);
    }
}

function generate5xxReportingEvent(error, request, responseCode) {
    try {
        const exception = new exceptionReporting(error, request, responseCode);
        if(!exception.traceId){
            return;
        }
        let key = (request.uri ? request.uri : request.url) + responseCode;
        if (!exceptionsMap.has(key)) {
            exceptionsMap.set(key, exception);
        }
        else {
            let previousCounter = exceptionsMap.get(key).counter;
            exception.counter = previousCounter ? previousCounter + 1: exception.counter + 1;
            exceptionsMap.set(key, exception);
        }
    } catch (err) {
        logger.debug("Error while generating 5xx application-runtime-error:", err);
    }
}



function startExceptionSendingSchedular() {
    try {
        setInterval(() => {
            const values = Array.from(exceptionsMap.values());
            for (let i = 0; i < values.length; i++) {
                API.sendEvent(values[i]);
            }
            exceptionsMap.clear();
        }, exceptionReportingInterval);
    } catch (error) {
        logger.info("Error in exception reporting schedular");
    }
    logger.info("Exception reporting schedular started");
}


module.exports = {
    exceptionReporting,
    createException,
    generateExceptionReportingEvent,
    generate5xxReportingEvent,
    startExceptionSendingSchedular
};
