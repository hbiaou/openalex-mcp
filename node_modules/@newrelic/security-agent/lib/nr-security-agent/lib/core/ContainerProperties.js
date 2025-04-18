/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let containerProperties = undefined;
function ContainerProperties(){
    
}
ContainerProperties.prototype.constructor = ContainerProperties;

/**
 * Returns the current instanceof ContainerProperties,
 * creates one if not already created.
 * 
 * @returns {ContainerProperties} instance
 */
function getInstance() {
    if (!containerProperties) {
        containerProperties = new ContainerProperties();
        containerProperties.name = "";
        containerProperties.isPrivileged = "";
        containerProperties.imageId = "";
        containerProperties.imageName = "";
        containerProperties.entrypoint = "";
        containerProperties.creationTimestamp = "";
        containerProperties.portBindings = new Map();
        containerProperties.mounts = [];
        containerProperties.state = "";
        containerProperties.processInfos = [];
        containerProperties.capAdd = [];
        containerProperties.capDrop = [];
        containerProperties.cpuUsage = "";
        containerProperties.ipAddress = "";

    }
    return containerProperties;
}

module.exports = {
    getInstance
};