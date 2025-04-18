/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

// eslint-disable-next-line no-unused-vars
const { LambdaDelegatedTaskType } = require('./lambda-delegated-task-type');
const { CSEC_TASK_PAYLOAD_IDENTIFIER } = require('./constants');

function LambdaDelegatedTaskBase (type, ...args) {
    this.type = type;
    this.args = args;
}

LambdaDelegatedTaskBase.prototype = Object.create(null);
LambdaDelegatedTaskBase.prototype.constructor = LambdaDelegatedTaskBase;

/**
 * Returns type of delegated task
 * @returns {LambdaDelegatedTaskType} type
 */
LambdaDelegatedTaskBase.prototype.getType = function getType () {
    return this.type;
};

/**
 * Returns delegated task args
 * @returns {Array} args
 */
LambdaDelegatedTaskBase.prototype.getArgs = function getArgs () {
    return this.args;
};

/**
 * Adds task delegation details to payload
 * @param {JSON} payload
 */
LambdaDelegatedTaskBase.prototype.addToPayload = function addToPayload (payload = {}) {
    payload[CSEC_TASK_PAYLOAD_IDENTIFIER] = {
        type: this.type,
        args: this.args
    };
    return payload;
};

LambdaDelegatedTaskBase.prototype.handle = function noop () {};

module.exports = {
    LambdaDelegatedTaskBase
};
