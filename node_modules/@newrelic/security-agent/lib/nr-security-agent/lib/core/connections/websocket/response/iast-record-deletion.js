/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let logger;
const IASTUtil = require('./IASTUtils');
module.exports.handler = function handler (json) {
    let deletionList =  json.arguments;
    let count = 0;
    deletionList.forEach(element => {
        count++;
        IASTUtil.removeRequestId(element);
    });
    logger.debug("Purging confirmed %s IAST processed records: ", count, JSON.stringify(deletionList));

};

module.exports.setLogger = l => { logger = l };
