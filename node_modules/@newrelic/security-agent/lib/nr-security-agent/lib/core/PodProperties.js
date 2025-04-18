/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let podProperties;
function PodProperties () {

}
PodProperties.prototype.constructor = PodProperties;

/**
 * Returns the current instanceof PodProperties,
 * creates one if not already created.
 *
 * @returns {PodProperties} instance
 */
function getInstance () {
    if (!podProperties) {
        podProperties = new PodProperties();
        podProperties.name = '';
        podProperties.namespace = '';
        podProperties.clusterName = '';
        podProperties.clusterId = '';
        podProperties.entrypoint = '';
        podProperties.ipAddress = '';
        podProperties.hostIpAddress = '';
        podProperties.creationTimestamp = '';
        podProperties.containerProperties = [];
    }
    return podProperties;
}

module.exports = {
    getInstance
};
