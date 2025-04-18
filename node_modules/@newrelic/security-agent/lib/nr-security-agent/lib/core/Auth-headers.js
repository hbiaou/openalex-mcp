/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const API = require('../../../nr-security-api');
const commonUtils = require('./commonUtils');
const appInfo = require('./applicationinfo').getInstance();
const logs = require('./logging');
const logger = logs.getLogger();
const initLogger = logs.getInitLogger();
const LinkingMetaData = require('./LinkingMetadata');
const LogMessage = require('./LogMessage');
const lodash = require('lodash');


/* eslint-disable camelcase */
let authHeaders;
/**
 * constructor to create Authentication Headers
 */
function AuthHeaders() {
    try {
        const NRAgent = API.getNRAgent();
        authHeaders = {}
        const metadata = LinkingMetaData.getLinkingMetadata();
        authHeaders['NR-CSEC-CONNECTION-TYPE'] = 'LANGUAGE_COLLECTOR';
        authHeaders['NR-AGENT-RUN-TOKEN'] = NRAgent.config.run_id;
        const COLLECTOR_VERSION = appInfo.collectorVersion || '';
        authHeaders['NR-CSEC-VERSION'] = COLLECTOR_VERSION.trim();
        authHeaders['NR-CSEC-COLLECTOR-TYPE'] = 'NODE';
        authHeaders['NR-CSEC-MODE'] = commonUtils.getCSECmode();
        authHeaders['NR-CSEC-APP-UUID'] = commonUtils.getUUID();
        authHeaders['NR-CSEC-JSON-VERSION'] = appInfo.jsonVersion;
        authHeaders['NR-CSEC-BUILD-NUMBER'] = appInfo.buildNumber;
        authHeaders['NR-ACCOUNT-ID'] = NRAgent.config.account_id;
        authHeaders['NR-LICENSE-KEY'] = NRAgent ? NRAgent.config.license_key : '';
        authHeaders["NR-CSEC-IAST-DATA-TRANSFER-MODE"] = "PULL";
        const entityName = metadata['entity.name'] ? metadata['entity.name'] : '';
        authHeaders['NR-CSEC-ENTITY-NAME'] = encodeURIComponent(entityName);
        authHeaders['NR-CSEC-ENTITY-GUID'] = metadata['entity.guid'] ? metadata['entity.guid'] : '';
        let instanceCount = parseInt(NRAgent.config.security.scan_controllers.scan_instance_count);
        if (isNaN(instanceCount)) {
            instanceCount = 0;
        }
        if (instanceCount < 0 || instanceCount > 1) {
            instanceCount = 0;
        }
        authHeaders['NR-CSEC-IAST-SCAN-INSTANCE-COUNT'] = instanceCount ? instanceCount : 0
        if ((NRAgent.config.security.iast_test_identifier && !lodash.isEmpty(NRAgent.config.security.iast_test_identifier)) || process.env.NEW_RELIC_SECURITY_IAST_TEST_IDENTIFIER) {
            let iast_test_identifier = NRAgent.config.security.iast_test_identifier || process.env.NEW_RELIC_SECURITY_IAST_TEST_IDENTIFIER
            authHeaders['NR-CSEC-IAST-TEST-IDENTIFIER'] = iast_test_identifier;
            logger.debug("iast_test_identifier is:", iast_test_identifier);
            authHeaders['NR-CSEC-IAST-SCAN-INSTANCE-COUNT'] = 1;
        }
        authHeaders['NR-CSEC-PROCESS-START-TIME'] = Date.now() - Math.floor(process.uptime() * 1000);
        authHeaders['NR-CSEC-IGNORED-VUL-CATEGORIES'] = commonUtils.listSkipDetectionCategory();
    } catch (error) {
        logger.error("Exception in preparing auth headers:", error);
        const logMessage = new LogMessage.logMessage("SEVERE", 'Exception in preparing auth headers', __filename, error);
        commonUtils.addLogEventtoBuffer(logMessage);
    }


    return authHeaders;
}
AuthHeaders.prototype.constructor = AuthHeaders;

/**
 * Returns the current instanceof AuthHeaders,
 * creates one if not already created.
 *
 * @returns {AuthHeaders} instance
 */
function getInstance() {
    if (!authHeaders) {
        authHeaders = new AuthHeaders();
        try {
            for (const key in authHeaders) {
                if (authHeaders.hasOwnProperty(key)) {
                    if (key != 'NR-LICENSE-KEY') {
                        logger.info(`Adding WS connection header: ${key} -> ${authHeaders[key]}`)
                    }
                    else {
                        logger.info(`Adding WS connection header: ${key} -> ******`)
                    }

                }
            }
        } catch (error) {
            logger.error("Error while getting authentication headers");
        }
    }
    return authHeaders;
}



module.exports = {
    getInstance
};