/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const LinkingMetaData = require('./LinkingMetadata');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();
const { BasicInfo } = require('./event');
const applicationInfo = require('./applicationinfo').getInstance();

/**
 * constructor function to create LogMessageException object
 * @param {*} message
 * @param {*} cause
 * @param {*} stacktrace
 */
function logMessageException(exception) {
    let exceptionObject = {};
    try {
        exceptionObject.message = exception.message ? exception.message : '';
        exceptionObject.cause = null;
        exceptionObject.type = exception.name;
        if (exception.stack) {
            let stacktraceInList = exception.stack.split('\n');
            stacktraceInList = stacktraceInList.slice(1);
            exceptionObject.stackTrace = stacktraceInList;
        }

    } catch (error) {

    }

    return exceptionObject;
}

/**
  * constructor function to create logMessage object;
  * @param {*} timestamp
  * @param {*} level
  * @param {*} message
  * @param {*} caller
  * @param {*} exception
  * @param {*} linkingMetadata
  */
function logMessage(level, message, caller, exception) {
    try {
        BasicInfo.call(this);
        this.jsonVersion = applicationInfo.jsonVersion;
        this.pid = applicationInfo.pid ? applicationInfo.pid : null;
        this.jsonName = 'critical-messages';
        this.applicationUUID = applicationInfo.applicationUUID;
        this.groupName = applicationInfo.groupName;
        this.policyVersion = applicationInfo.policyVersion;
        this.collectorVersion = applicationInfo.collectorVersion ? applicationInfo.collectorVersion : null;
        this.buildNumber = applicationInfo.buildNumber ? applicationInfo.buildNumber : null;
        this.timestamp = Date.now();
        this.level = level ? level : 'SEVERE';
        this.message = message;
        this.caller = caller;
        if (exception) {
            this.exception = logMessageException(exception);
        }
        if (NRAgent) {
            this.linkingMetadata = LinkingMetaData.getLinkingMetadata();
        }
    } catch (error) {

    }

}

module.exports = {
    logMessage,
    logMessageException
};
