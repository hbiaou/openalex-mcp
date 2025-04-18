/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const { LambdaDelegatedTaskBase } = require('./lambda-delegated-task-base');
const ApplicationInfo = require('../../core/applicationinfo');
const { Agent } = require('../../core/agent');
const shaSizeUtil = require('../../core/sha-size-util');
const { CSEC_CALCULATING_APPLICATION_SHA } = require('./constants');
function LambdaDelegatedTaskShaCalculation (type, ...args) {
    LambdaDelegatedTaskBase.call(this, type, ...args);
}

LambdaDelegatedTaskShaCalculation.prototype = LambdaDelegatedTaskBase.prototype;
LambdaDelegatedTaskShaCalculation.prototype.constructor = LambdaDelegatedTaskShaCalculation;

LambdaDelegatedTaskShaCalculation.prototype.handle = function handleShaCalculation () {
    process.env[CSEC_CALCULATING_APPLICATION_SHA] = true;
    const applicationInfo = ApplicationInfo.getInstance();
    const deployedApplications = applicationInfo && applicationInfo.serverInfo && applicationInfo.serverInfo.deployedApplications;

    // if there are no applications detected
    if (!deployedApplications) return;

    // calculate and add sha and size info
    const [application] = deployedApplications;
    const stat = shaSizeUtil.getApplicationSHAAndSizeSync(application.deployedPath, /.*\/(node_modules)\/.*/);
    application.sha256 = stat.sha256;
    application.size = stat.size;

    Agent.getAgent().client.dispatcher(applicationInfo);
};

module.exports = {
    LambdaDelegatedTaskShaCalculation
};
