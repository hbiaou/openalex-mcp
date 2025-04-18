/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const { BasicInfo } = require('./event');
const applicationInfo = require('./applicationinfo').getInstance();
/**
 * Function Constructor to create object of FuzzFail event
 * @param {*} fuzzHeader
 */
function FuzzFailEvent (fuzzHeader) {
    BasicInfo.call(this);
    this.jsonVersion = applicationInfo.jsonVersion;
    this.jsonName = 'fuzzfail';
    this.applicationUUID = applicationInfo.applicationUUID;
    this.groupName = applicationInfo.groupName;
    this.nodeId = applicationInfo.nodeId;
    this.policyVersion = applicationInfo.policyVersion;
    this.fuzzHeader = fuzzHeader;
}

FuzzFailEvent.prototype.constructor = FuzzFailEvent;

module.exports = {
    FuzzFailEvent
};
