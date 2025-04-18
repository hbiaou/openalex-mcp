/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */
const { platform } = require('os');
const path = require('path');

let AGENT_DIR = path.join(__dirname, '../../../');

if(process.platform == 'win32'){
    AGENT_DIR = path.join(__dirname, "..\\..\\..\\");
}

const uuid = require('uuid');
process.env.applicationUUID = process.env.applicationUUID || uuid.v4();

module.exports = {
    AGENT_DIR,
    ENV: process.env.CSEC_ENV,
    APPLICATION_INFO_PUBLISH_MAX_WAIT: 10000, // milliseconds
    HC_INTERVAL_MS: 300000, // milliseconds
    MAX_PENDING_QUEUE_LENGTH: 1000,
    MAX_EVENT_RATE: 1200, // EVENTS/sec
    DEFAULT_LOG_CHANGETIME: 300000 // milliseconds
};
