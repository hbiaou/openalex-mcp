/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let logger;

module.exports.handler = function handler (json) {
    logger.error('unsupported control command received:', json);
};

module.exports.setLogger = l => { logger = l };
