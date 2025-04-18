/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let logger;

module.exports.handler = function handler (json) {
    logger.debug('IAST cool down command received:', JSON.stringify(json));
    const fuzzRequestHandler = require('./fuzz-request-handler');
    fuzzRequestHandler.setLastFuzzEventTime();
    fuzzRequestHandler.setAdditionalCoolDown(json.data);
};

module.exports.setLogger = l => { logger = l };
