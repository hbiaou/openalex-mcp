
/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let logger;

module.exports.handler = function handler(json) {
    try {
        const policyData = json.data;
        const PolicyManager = require('../../../Policy');
        PolicyManager.setPolicyData(policyData);
        if (policyData.vulnerabilityScan.enabled && policyData.vulnerabilityScan.iastScan.enabled) {
            require('./fuzz-request-handler').startIASTSchedular();
        }

    } catch (error) {
        logger.error('paring exception while parsing configuration', error);
    }
};

module.exports.setLogger = l => { logger = l };