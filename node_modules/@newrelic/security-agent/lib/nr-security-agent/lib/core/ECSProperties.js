/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let ecsProperties;
function ECSProperties () {

}
ECSProperties.prototype.constructor = ECSProperties;

/**
 * Returns the current instanceof ECSProperties,
 * creates one if not already created.
 *
 * @returns {ECSProperties} instance
 */
function getInstance () {
    if (!ecsProperties) {
        ecsProperties = new ECSProperties();
        ecsProperties.imageName = '';
        ecsProperties.imageId = '';
        ecsProperties.containerName = '';
        ecsProperties.containerId = '';
        ecsProperties.ecsTaskDefinition = '';
        ecsProperties.ipAddress = '';
        ecsProperties.creationTimestamp = '';
    }
    return ecsProperties;
}

module.exports = {
    getInstance
};
