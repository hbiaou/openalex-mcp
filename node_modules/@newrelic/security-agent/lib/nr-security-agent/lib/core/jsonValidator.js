/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const Validator = require('jsonschema').Validator;
const v = new Validator();
const schema = {
    title: 'LCPolicy',
    description: 'A policy for language collectors',
    type: 'object',
    properties: {
        version: {
            type: 'string',
            minLength: 1
        },
        policyPull: {
            type: 'boolean'
        },
        policyPullInterval: {
            type: 'integer',
            minimum: 0,
            maximum: 2678400
        },
        vulnerabilityScan: {
            type: 'object',
            properties: {
                enabled: {
                    type: 'boolean'
                },
                iastScan: {
                    type: 'object',
                    properties: {
                        enabled: {
                            type: 'boolean'
                        },
                        probing: {
                            type: 'object',
                            properties: {
                                interval: {
                                    type: 'integer',
                                    minimum: 1,
                                    maximum: 60
                                },
                                batchSize: {
                                    type: 'integer',
                                    minimum: 1,
                                    maximum: 300
                                }
                            },
                            required: [
                                'interval',
                                'batchSize'
                            ]
                        }
                    },
                    required: [
                        'enabled',
                        'probing'
                    ]
                }
            },
            required: [
                'enabled',
                'iastScan'
            ]
        },
        protectionMode: {
            type: 'object',
            properties: {
                enabled: {
                    type: 'boolean'
                },
                ipBlocking: {
                    type: 'object',
                    properties: {
                        enabled: {
                            type: 'boolean'
                        },
                        attackerIpBlocking: {
                            type: 'boolean'
                        },
                        ipDetectViaXFF: {
                            type: 'boolean'
                        }
                    },
                    required: [
                        'enabled',
                        'attackerIpBlocking',
                        'ipDetectViaXFF'
                    ]
                },
                apiBlocking: {
                    type: 'object',
                    properties: {
                        enabled: {
                            type: 'boolean'
                        },
                        protectAllApis: {
                            type: 'boolean'
                        },
                        protectKnownVulnerableApis: {
                            type: 'boolean'
                        },
                        protectAttackedApis: {
                            type: 'boolean'
                        }
                    },
                    required: [
                        'enabled',
                        'protectAllApis',
                        'protectKnownVulnerableApis',
                        'protectAttackedApis'
                    ]
                }
            },
            required: [
                'enabled',
                'ipBlocking',
                'apiBlocking'
            ]
        },
        sendCompleteStackTrace: {
            type: 'boolean'
        },
        enableHTTPRequestPrinting: {
            type: 'boolean'
        }
    },
    required: [
        'version',
        'policyPull',
        'policyPullInterval',
        'vulnerabilityScan',
        'protectionMode',
        'sendCompleteStackTrace',
        'enableHTTPRequestPrinting'
    ]
};

function validate (data) {
    const result = v.validate(data, schema);
    return result;
}


module.exports = {
    validate
};
