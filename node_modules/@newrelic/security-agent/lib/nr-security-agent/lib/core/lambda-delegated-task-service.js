/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const { Agent } = require('./agent');
const { AWS_LAMBDA_FUNCTION_VERSION_ENV_IDENTIFIER } = require('./sec-agent-constants');
const { invokeLambda } = require('./connections/aws-lambda-client');
const {
    LambdaDelegatedTaskType,
    LambdaDelegatedTaskBase,
    LambdaDelegatedTaskShaCalculation,
    CONST
} = require('../models/lambda-delegated-task');

const CSEC_TASK_PAYLOAD_IDENTIFIER = 'CSEC_TASK_PAYLOAD';

let instance;
function LambdaDelegatedTaskService () {}

LambdaDelegatedTaskService.prototype = Object.create(null);
LambdaDelegatedTaskService.prototype.constructor = LambdaDelegatedTaskService;

/**
 * generates a lambda delegated task object
 * @param {LambdaDelegatedTaskType} type
 * @param  {...any} args
 * @returns {LambdaDelegatedTaskBase} obj
 */
LambdaDelegatedTaskService.prototype.generateHandler = function generateHandler (type, ...args) {
    switch (type) {
    case LambdaDelegatedTaskType.SHA_CALCULATION:
        return new LambdaDelegatedTaskShaCalculation(type, ...args);
    default:
        return new LambdaDelegatedTaskBase(type, ...args);
    }
};

/**
 * Detectects if the lambda event contains a delegated task
 * payload.
 * @param {JSON} event
 * @returns {LambdaDelegatedTaskBase} obj
 */
LambdaDelegatedTaskService.prototype.detectInEvent = function detectInEvent (event) {
    if (event && event[CSEC_TASK_PAYLOAD_IDENTIFIER]) {
        const { type, args } = event[CSEC_TASK_PAYLOAD_IDENTIFIER];
        if (!Array.isArray(args)) return undefined;

        return this.generateHandler(type, ...args);
    }
    return undefined;
};

/**
 * invokes current lambda function with passed lambda
 * delegated task object as the payload.
 * @param {LambdaDelegatedTaskBase} lambdaDelegatedTaskObject
 */
LambdaDelegatedTaskService.prototype.delegate = function delegate (lambdaDelegatedTaskObject) {
    const payload = lambdaDelegatedTaskObject.addToPayload();
    const qualifiedARN = Agent.getAgent().applicationInfo.applicationUUID;
    const splitArn = String.prototype.split.call(qualifiedARN, ':');
    const arn = splitArn.slice(0, splitArn.length - 1).join(':');
    const ver = process.env[AWS_LAMBDA_FUNCTION_VERSION_ENV_IDENTIFIER];
    invokeLambda(arn, ver, payload);
};

/**
 * Returns a singleton instance of LambdaDelegatedTaskService
 * @returns {LambdaDelegatedTaskService} instance
 */
LambdaDelegatedTaskService.getInstance = function () {
    return instance || LambdaDelegatedTaskService.createInstance();
};

/**
 * Creates and returns a new instance of LambdaDelegatedTaskService
 * @returns {LambdaDelegatedTaskService} instance
 */
LambdaDelegatedTaskService.createInstance = function () {
    instance = new LambdaDelegatedTaskService();
    return instance;
};

module.exports = {
    LambdaDelegatedTaskService,
    LambdaDelegatedTaskType,
    CONST
};
