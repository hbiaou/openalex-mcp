/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

let newrelic;
let NRAgent;

/**
 * 
 * @returns NewRelic Agent instance
 */
function getNRAgent() {
    if (NRAgent && NRAgent.config && !NRAgent.config.security.scan_schedule) {
        NRAgent.config.security.scan_schedule = {};
        NRAgent.config.security.scan_schedule.delay = 0;
        NRAgent.config.security.scan_schedule.duration = 0;
        NRAgent.config.security.scan_schedule.schedule = '';
        NRAgent.config.security.scan_schedule.always_sample_traces = false;

    }
    if ( NRAgent && NRAgent.config && !NRAgent.config.security.scan_controllers) {
        NRAgent.config.security.scan_controllers = {};
        NRAgent.config.security.scan_controllers.iast_scan_request_rate_limit = 3600;
        NRAgent.config.security.scan_controllers.scan_instance_count = 0;
    }
    if (NRAgent && NRAgent.config && !NRAgent.config.security.exclude_from_iast_scan) {
        NRAgent.config.security.exclude_from_iast_scan = {};
        NRAgent.config.security.exclude_from_iast_scan.api = [];
        NRAgent.config.security.exclude_from_iast_scan.http_request_parameters = {};
        NRAgent.config.security.exclude_from_iast_scan.http_request_parameters.header = [];
        NRAgent.config.security.exclude_from_iast_scan.http_request_parameters.query = [];
        NRAgent.config.security.exclude_from_iast_scan.http_request_parameters.body = [];
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category = {};
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.insecure_settings = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.invalid_file_access = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.sql_injection = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.nosql_injection = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.ldap_injection = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.javascript_injection = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.command_injection = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.xpath_injection = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.ssrf = false;
        NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.rxss = false;
    }
    return NRAgent;
}

/**
 * API to set newrelic agent object.
 * @param {*} agent 
 */
function setNRAgent(agent) {
    NRAgent = agent;
}

/**
 * API to get security agent
 * @returns Security Agent instanace
 */
function getSecAgent() {
    const Agent = require('../nr-security-agent/lib/core/agent').Agent;
    const csecAgent = Agent.getAgent();
    if (csecAgent) {
        return csecAgent;
    }
}

/**
 * API to get status of security agent
 * @returns Security Agent status
 */
function getSecAgentStatus() {
    const Agent = require('../nr-security-agent/lib/core/agent').Agent;
    if (Agent.getAgent()) {
        return Agent.getAgent().status.getStatus()
    }
}

/**
 * API to generate security event from the intermediate data
 * @param {*} securityMetadata 
 * @returns security event object
 */
function generateSecEvent(securityMetadata) {
    return require('../nr-security-agent/lib/core/sec-util').generateSecEvent(securityMetadata);
}

/**
 * API to send security event 
 * @param {*} secEvent 
 */
function sendEvent(secEvent) {
    require('../nr-security-agent/lib/core/sec-util').sendEvent(secEvent);
}

/**
 * API to get logger instance
 * @returns 
 */
function getLogger() {
    return require('../nr-security-agent/lib/core/logging').getLogger();
}
/**
 * API to validate RXSS
 * @param {*} secRequest 
 * @param {*} responseBody 
 * @param {*} responseHeaders 
 * @returns 
 */
function checkForReflectedXSS(secRequest, responseBody, responseHeaders) {
    return require('../nr-security-agent/lib/core/xss-utils').checkForReflectedXSS(secRequest, responseBody, responseHeaders);
}

/**
 * API to get security agent policy
 * @returns security agent policy
 */
function getPolicy() {
    return require('../nr-security-agent/lib/core/Policy').getInstance();
}

/**
 * API to generate Exit event
 * @param {*} event 
 */
function generateExitEvent(event) {
    require('../nr-security-agent/lib/core/sec-util').generateExitEvent(event);
}

module.exports = {
    newrelic,
    getNRAgent,
    getSecAgent,
    getSecAgentStatus,
    generateSecEvent,
    sendEvent,
    getLogger,
    checkForReflectedXSS,
    getPolicy,
    generateExitEvent,
    setNRAgent
}