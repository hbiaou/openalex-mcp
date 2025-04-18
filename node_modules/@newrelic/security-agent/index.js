/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Pre-Release
 */

const API = require('./lib/nr-security-api');
/**
 * Entry point of CSEC agent.
 * @param {*} agent  newrelic agent object
 * @returns 
 */
function start(NRAgentObject) {
    const agent = NRAgentObject.agent;
    API.newrelic = NRAgentObject;
    API.setNRAgent(agent);
    if (agent.config.high_security) {
        return;
    }
    require('./lib/nr-security-agent');
}
module.exports = {
    API,
    start
}
