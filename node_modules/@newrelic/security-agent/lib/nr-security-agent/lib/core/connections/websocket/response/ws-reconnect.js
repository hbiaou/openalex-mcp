/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let logger;
const { Agent } = require('../../../agent');
module.exports.handler = function handler (json) {
    if (Agent.getAgent().status.getStatus() != 'disabled'){
        logger.info('WS reconnect received', json);
        const wsClient = Agent.getAgent().client;
        wsClient.obeyReconnect();
    }
    
};

module.exports.setLogger = l => { logger = l };
