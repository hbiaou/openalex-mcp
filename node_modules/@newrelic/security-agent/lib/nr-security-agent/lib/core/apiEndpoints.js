
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
function APIEndPoint (apiEndpoints) {
    BasicInfo.call(this);
    this.jsonVersion = applicationInfo.jsonVersion;
    this.jsonName = 'sec-application-url-mapping';
    this.eventType = "sec-application-url-mapping"
    this.applicationUUID = applicationInfo.applicationUUID;
    this.groupName = applicationInfo.groupName;
    this.mappings = apiEndpoints;

    return this;
}

APIEndPoint.prototype.constructor = APIEndPoint;

module.exports = {
    APIEndPoint
};
