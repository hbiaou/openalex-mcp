/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */
const SecAgentStatus = function () {
    if (Object.getPrototypeOf(this).constructor !== SecAgentStatus) {
        return new SecAgentStatus();
    }
    if (!SecAgentStatus.instance) {
        SecAgentStatus.instance = this;
        let status = SecAgentStatus.codes.CONNECTING;
        const codeList = [];
        for (let code in SecAgentStatus.codes) {
            codeList.push(SecAgentStatus.codes[code])
        }
        this.getStatus = function () {
            return status;
        }
        this.setStatus = function (STATUS) {
            if (STATUS && codeList.includes(STATUS)) {
                status = STATUS;
            } else {
                throw new Error("Unknown Status");
            }
        }
    } else {
        return SecAgentStatus.instance;
    }
}
SecAgentStatus.prototype.constructor = SecAgentStatus;

/**
 * Valid values to set agent status.
 */
SecAgentStatus.codes = {
    CONNECTING: 'connecting',
    ACTIVE: "active",
    DISABLED: "disabled",
    DETACHED: "detached",
    INACTIVE:'inactive'
}

/**
 * Get instance of CSECAgentStatus.
 */
const getInstance = function () {
    if (!SecAgentStatus.instance) {
        return new SecAgentStatus();
    } else {
        return SecAgentStatus.instance;
    }
}

module.exports = {
    CSECAgentStatus: SecAgentStatus,
    getInstance
};