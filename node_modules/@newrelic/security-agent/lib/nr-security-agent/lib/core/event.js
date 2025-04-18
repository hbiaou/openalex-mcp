/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';
const { JSON_NAME, COLLECTOR_TYPE, LANGUAGE, EMPTY_STR, STRING, NR_CSEC_FUZZ_REQUEST_ID } = require('./sec-agent-constants');
const { AGENT_VERSION } = require('../../resources/config');
const policyManager = require('./Policy');
const LinkingMetaData = require('./LinkingMetadata');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();
const lodash = require('lodash');
const commonUtils = require('./commonUtils');
const crypto = require('crypto');
/**
* BasicInfo Structure, which is applicatble to each
* Event generated from agent.
*/
function BasicInfo() {
    this.jsonName = undefined;
    this.pid = undefined;
    this.applicationUUID = undefined;
    this.timestamp = Date.now();
    this.jsonVersion = AGENT_VERSION;
    this.collectorType = COLLECTOR_TYPE;
    this.language = LANGUAGE;
    try {
        let framework = NRAgent.environment.get('Framework')[0];
        this.framework = framework ? framework : EMPTY_STR;
    } catch (error) {
        this.framework = EMPTY_STR;
    }
    this.groupName = commonUtils.getCSECmode();
    this.policyVersion = (!lodash.isEmpty(policyManager.getInstance().data)) ? policyManager.getInstance().data.version : 'DEFAULT';

    if (NRAgent && NRAgent.config) {
        this.appAccountId = NRAgent.config.account_id;
        this.appEntityGuid = NRAgent.config.entity_guid;
        this.linkingMetadata = LinkingMetaData.getLinkingMetadata();
        this.linkingMetadata.agentRunId = NRAgent.config.run_id;
    }
}

/**
* Creates a new Event Object from the passed info.
*
* @param {string} fileName
* @param {string} funcName
* @param {number} lineNumber
* @param {*} argument
* @param {number} eid
* @param {ApplicationInfo} applicationInfo
* @param {Object} httpRequest
* @param {string} jsonName
* @param {string} eventName
* @param {Object} source
*
* @returns {SecEvent} event
*/

function SecEvent(fileName, funcName, lineNumber, argument, eid, applicationInfo, httpRequest, eventName, source, eventCategory, metaData, stkTrace, apiId, isAPIBlocked) {
    BasicInfo.call(this);
    const policy = policyManager.getInstance();
    if (argument) {
        argument = argument instanceof Array ? argument : [argument];
    } else if (typeof argument === STRING) {
        argument = [argument];
    } else {
        argument = null;
    }
    this.jsonVersion = applicationInfo.jsonVersion ? applicationInfo.jsonVersion : null;
    this.collectorVersion = applicationInfo.collectorVersion ? applicationInfo.collectorVersion : null;
    this.buildNumber = applicationInfo.buildNumber ? applicationInfo.buildNumber : null;
    this.source = source || null;
    this.applicationUUID = applicationInfo.applicationUUID ? applicationInfo.applicationUUID : null;
    this.jsonName = JSON_NAME.EVENT;
    this.userFileName = fileName || null;
    this.userMethodName = funcName || null;
    try {
        lineNumber = parseInt(lineNumber);
    } catch (error) {
    }
    this.lineNumber = lineNumber || -1;
    this.parameters = argument;
    this.eventGenerationTime = new Date().getTime();
    this.eid = eid || null;
    this.pid = applicationInfo.pid ? applicationInfo.pid : null;
    this.httpRequest = httpRequest || null;
    this.caseType = eventName || null;
    this.eventCategory = eventCategory || null;
    this.metaData = metaData || {
        TRIGGER_VIA_RCI: false,
        RCI_METHOD_CALLS: []
    };
    this.stacktrace = stkTrace;
    this.apiId = apiId || null;
    this.isAPIBlocked = isAPIBlocked || false;
    const vulnerabilityScan = policy.data.vulnerabilityScan;
    const dynamicScanning = vulnerabilityScan.enabled && vulnerabilityScan.iastScan.enabled;
    this.isIASTEnable = dynamicScanning;
    if (this.isIASTEnable) {
        this.id = eid + Math.floor(crypto.randomInt(100) * (100000 - 1) + 1);
    } else {
        this.id = eid;
    }
    if (httpRequest && httpRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        this.isIASTRequest = true;
        this.parentId = httpRequest.headers['nr-csec-parent-id'];
    }
    else {
        this.isIASTRequest = false;
    }
    this.eventType = 'sec_event';
    if (NRAgent) {
        const nrTransaction = NRAgent.getTransaction();
        if (nrTransaction) {
            this.linkingMetadata.transactionId = nrTransaction.id;
            const segment = NRAgent.tracer.getSegment();
            if (segment) {
                this.linkingMetadata['span.id'] = segment.getSpanId();
            }
            this.linkingMetadata.isSampled = nrTransaction.isSampled();
            this.linkingMetadata['trace.id'] = nrTransaction.traceId;
        }
    }
}

SecEvent.prototype = Object.create(BasicInfo.prototype);
SecEvent.prototype.constructor = SecEvent;

module.exports = {
    BasicInfo,
    SecEvent: SecEvent,
    EVENT_TYPE: {
        SYSTEM_COMMAND: 'SYSTEM_COMMAND',
        SYSTEM_EXIT: 'SYSTEM_EXIT',
        FILE_OPERATION: 'FILE_OPERATION',
        FILE_INTEGRITY: 'FILE_INTEGRITY',
        DB_COMMAND: 'SQL_DB_COMMAND',
        NOSQL_DB_COMMAND: 'NOSQL_DB_COMMAND',
        HTTP_REQUEST: 'HTTP_REQUEST',
        CODE_INJECTION: 'CODE_INJECTION',
        XXE: 'XXE',
        CIPHER: 'CIPHER',
        HASH: 'HASH',
        RANDOM: 'RANDOM',
        UNVALIDATED_REDIRECT: 'UNVALIDATED_REDIRECT',
        REFLECTED_XSS: 'REFLECTED_XSS',
        XPATH: 'XPATH',
        LDAP: 'LDAP'

    },
    EVENT_CATEGORY: {
        MYSQL: 'MYSQL',
        POSTGRES: 'POSTGRES',
        ORACLE: 'ORACLE',
        MONGO: 'MONGO',
        MSSQL: 'MSSQL',
        SQLITE: 'SQLITE',
        FILE: 'FILE',
        SYS: 'SYSTEM',
        HTTP: 'HTTP',
        CODE_INJECTION: 'CODE_INJECTION',
        XXE: 'XXE',
        CRYPTO: 'CRYPTO',
        HASH: 'HASH',
        WEAKRANDOM: 'WEAKRANDOM',
        UNVALIDATED_REDIRECT: 'UNVALIDATED_REDIRECT',
        REFLECTED_XSS: 'REFLECTED_XSS',
        XPATH: 'XPATH',
        LDAP: 'LDAP'
    },

    VUNERABILITIES:
    {
        SQLI: 'SQLI',
        SXSS: 'SXSS',
        RXSS: 'RXSS',
        LDAP: 'LDAP',
        RCE: 'RCE',
        RCI: 'RCI',
        FILE_ACCESS: 'FILE_ACCESS',
        NOSQLI: 'NOSQLI',
        WEAK_RANDOM: 'WEAK_RANDOM',
        XPATH: 'XPATH',
        SSRF: 'SSRF',
        CRYPTO: 'CRYPTO',
        HASH: 'HASH',
        XXE: 'XXE',
        UNVALIDATED_REDIRECT: 'UNVALIDATED_REDIRECT'
    }

};
