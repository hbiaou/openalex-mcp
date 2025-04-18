/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const AWS_LAMBDA_NODE_EXEC_ENV_IDENTIFIER = /^AWS_Lambda_nodejs.*$/g;
const AWS_EXECUTION_ENV_VAR = 'AWS_EXECUTION_ENV';
const path = require('path');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();
const sep = require('path').sep;

let CSEC_HOME = NRAgent && NRAgent.config.newrelic_home ? NRAgent.config.newrelic_home : NRAgent && NRAgent.config.logging.filepath ? path.dirname(NRAgent.config.logging.filepath) : require('path').join(process.cwd());
const CSEC_GROUP_NAME = NRAgent ? NRAgent.config.security.mode : 'IAST';
CSEC_HOME = path.resolve(CSEC_HOME);
const agentStartTime = new Date().toString();

module.exports = {
    CSEC_HOME: CSEC_HOME,
    CSEC_GROUP_NAME: CSEC_GROUP_NAME,
    LOG_DIR: `${CSEC_HOME}${sep}nr-security-home${sep}logs${sep}`,
    CSEC_HOME_TMP: `${CSEC_HOME}${sep}nr-security-home${sep}tmp${sep}language-agent${sep}${process.env.applicationUUID}`,
    AGENT_START_TIME: agentStartTime,
    FRAMEWORK: '',
   
    DB_LIST: {
        MYSQL: 'MYSQL',
        MYSQL2: 'MYSQL',
        POSTGRES: 'POSTGRES',
        MONGODB: 'MONGODB',
        ORACLEDB: 'ORACLEDB',
        MSSQL: 'MSSQL',          
        SQLITE3: 'SQLITE3'
    },
    SERVER_COMMAND: {
        SET_LOG_LEVEL: 0,
        SHUTDOWN_LANGUAGE_AGENT: 1,
        SET_DEFAULT_LOG_LEVEL: 2,
        ENABLE_HTTP_REQUEST_PRINTING: 3,
        UPLOAD_LOGS: 4,
        UNSUPPORTED_AGENT: 5,
        VALIDATION_RESPONSE: 6,
        START_VULNERABILITY_SCAN: 8,
        STARTUP_WELCOME_MSG: 10,
        FUZZ_REQUEST: 11,
        COLLECTOR_CONFIG: 100,
        BLOCKING: 101,
        POLICY_ERROR: 102,
        OBEY_WS_RECONNECT: 12,
        ENTER_IAST_COOLDOWN: 13,
        IAST_RECORD_DELETE_CONFIRMATION: 14

    },
    JSON_NAME: {
        EVENT: 'Event',
        HC: 'LAhealthcheck',
        SD: 'Shutdown',
        APP_INFO: 'ApplicationInfo',
        ICC: 'IntCodeControlCommand',
        CONNSTAT: 'http-connection-stat'
    },
    COLLECTOR_TYPE: 'NODE',
    LANGUAGE: 'JavaScript',
    AWS_LAMBDA_QUALIFIED_ARN_ENV_IDENTIFIER: 'AWS_LAMBDA_ARN',
    AWS_LAMBDA_FUNCTION_NAME_ENV_IDENTIFIER: 'AWS_LAMBDA_FUNCTION_NAME',
    AWS_LAMBDA_FUNCTION_VERSION_ENV_IDENTIFIER: 'AWS_LAMBDA_FUNCTION_VERSION',
    AWS_SESSION_TOKEN_ENV_IDENTIFIER: 'AWS_SESSION_TOKEN',
    LAMBDA_TASK_ROOT_ENV_IDENTIFIER: 'LAMBDA_TASK_ROOT',
    LAMBDA_ENABLE_RESPONSE_BLOCKING: 'LAMBDA_ENABLE_RESPONSE_BLOCKING',
    AWS_LAMBDA_NODE_EXEC_ENV_IDENTIFIER,
    AWS_EXECUTION_ENV_VAR,
    IS_LAMBDA_ENV: Array.isArray(
        (process.env[AWS_EXECUTION_ENV_VAR] || '').match(AWS_LAMBDA_NODE_EXEC_ENV_IDENTIFIER)
    ),
    LAMBDA_RUNTIME_DIR_VAR: 'LAMBDA_RUNTIME_DIR',
    NR_CSEC_FUZZ_REQUEST_ID: 'nr-csec-fuzz-request-id',
    EMPTY_APPLICATION_UUID: '--0--',
    QUESTIONMARK: '?',
    PIPE_SEP: '|',
    ATTHERATE: '@',
    EMPTY_STR: '',
    COLON: ':',
    OPEN_PARANTHESIS: '(',
    CLOSE_PARANTHESIS: ')',
    SLASH: sep,
    INCOMING_MSG: 'IncomingMessage',
    OBJECT: 'object',
    STRING: 'string',
    TRIGGER_VIA_RCI: 'triggerViaRCI',
    RCI_METHOD_CALLS: 'rciMethodsCalls',
    VULNERABLE: 'VULNERABLE',
    UTF8: 'utf8',
    CONTENT_TYPE: 'content-type',
    TEXT_HTML: 'text/html',
    APPLICATION_JSON: 'application/json',
    APPLICATION_XML: 'application/xml',
    APPLICATION_XHTML: 'application/xhtml+xml',
    TEXT_PLAIN: 'text/plain',
    APPLICATION_X_FORM_URLENCODED: 'application/x-www-form-urlencoded',
    MULTIPART_FORM_DATA: 'multipart/form-data',
    XFORFOR: 'x-forwarded-for',
    DOUBLE_DOLLAR: '$$',
    LOADING_MODULE: 'Loading module ',
    EXITEVENT: 'exit-event',
    CSEC_SEP: ':IAST:',
    RASP: 'RASP',
    IAST: 'IAST',
    SEVERE: 'SEVERE',
    HIGH: 'HIGH',
    CRITICAL: 'CRITICAL',
    HYPHEN: '-',

    LOG_MESSAGES: {
        LOADED_CSEC_ENVS_MSG: '[STEP-1][COMPLETE][env] Environment Information Gathering Done.',
        AGENT_INFO: 'Security Agent version : %s, json version : %s, build number : %s',
        APP_INFO_GATHERING_STARTED: '[STEP-1][BEGIN][APP_INFO] Gathering Application Info For Current Process.',
        DEP_APP_GATHERING_STARTED: '[BEGIN][APP_INFO][DEPLOYED_APP] Gathering deployed application info for current process',
        APP_INFO_DEP_APP: '[APP_INFO][DEPLOYED_APP] Deployed application info generated :%s',
        AGENT_INIT_SUCCESSFUL: '[STEP-3][protection][BEGIN] Node CSEC Agent Attached To Process: PID = %s, With Generated Applicationuid = %s By Static Attachment',
        AGENT_INIT_SUCCESSFUL_COMPLETE: '[STEP-3][PROTECTION][COMPLETE] Protecting new process with PID = %s and UUID = %s',
        AGENT_INIT_FAILED: '[protection] Coudn\'t Initiate CSEC Agent For Process: : Pid = {pid}, With Generated Applicationuid = {application_uuid}.',
        LOG_FILE_INITIATED_MSG: 'Init Log File Initiated.',
        LOG_CONFIGURED_SUCCESSFULLY_MSG: 'Init Logger Configured Successfully With Level: %s And Rollover On Max Size %s.',
        INIT_APPINFO_SEND: '[STEP-9][COMPLETE][APP_INFO][DEPLOYED_APP] Updated ApplicationInfo Will Be Sent To Prevent-web Service',
        AGENT_ATTACH_FAIL: 'CSEC_GROUP_NAME Environment Not Present, Agent Attachment Failed',
        APP_INFO_GENERATED: '[APP_INFO] Application Info Generated: %s ',
        SCHED_SERVICE_START: '[STEP-5][BEGIN][MODULE] Start Threads/pools/scheduler',
        SCHED_SERVICE_START_BEG: '[BEGIN][MODULE] Started Threads/pools/scheduler',
        START_HC: '[BEGIN][MODULE] Starting Healthcheck',
        START_IOM: '[BEGIN][MODULE] Starting Inboundoutboundmonitor.',
        END_HC: '[COMPLETE][MODULE] Started Healthcheck',
        END_IOM: '[COMPLETE][MODULE] Started Inboundoutboundmonitor.',
        START_DIR_WATCH: '[BEGIN][MODULE] Starting DirectoryWatcher',
        STARTED_DIR_WATCH: '[COMPLETE][MODULE] Started DirectoryWatcher',
        NODE_VERSION_MSG: 'Node Version Is %s, Starting Websocket Client In Parent Process',
        NODE_VERSION_MSG_WORKER: 'Node Version Is %s, Starting Websocket Client In Worker Thread',
        MSG_FROM_WORKKER: 'Message From Worker Thread:',
        RECV_POL_DATA: '[STEP-7][BEGIN][POLICY] Received Policy Data From Prevent-web Service:%s',
        RECV_GLOBAL_POL_DATA: 'Received Global Policy Parameters From Prevent-web Service:%s',
        EXP_RAISE_GLOBAL_POL: 'Exception Raised In Global Policy Validation:',
        UNABLE_TO_WRITE_TO_POL_FILE: 'Unable To Write To Policy Yaml File',
        POL_UPDATE_SUCCESS: 'Policy Updated To File Successfully',
        CHANGE_DETECT_POL_FILE: 'Changes Detected In Policy File',
        ERROR_READ_FROM_POL_FILE: 'ERROR In Reading Policy From File',
        POL_UPDATE_RESP: 'Policy Update Response Is:',
        UPDATE_POL_SENT_SERVER: 'Updated Policy Sent To Prevent Web',
        EXP_RAISE_POL: 'Exception Raised In Policy Validation:',
        FALLBACK_TO_CURR_POLICY: 'Fallback To Current Policy!!!:%s',
        POLICY_APPLIED: 'Received and applied policy/configuration :',
        POL_PULL_INT_IS: 'Policy Pull Interval Is:',
        LOG_LEVEL_UPDATED: 'Log Level Updated To:',
        DEFAULT_POL_SET: 'Default Policy Has Been Set :',
        UNABLE_SET_DEFAULT_POL: 'Unable To Set Default Policy',
        AGENT_INIT_WITH_PROP: 'Security Agent is initialized with properties:',
        PARSING_EXP_WELCOME_MSG: 'Parsing Exeception In Startup Welcome Command',
        ACCESS_BLOCKED_IP_DETECTED: 'Access By Blocked Ip Address Detected : ',
        FIRST_EVENT_INTERCEPTED: '[BEGIN][EVENT] First event intercepted',
        FIRST_EVENT_PROCESSED: '[EVENT] First event processed :',
        FIRST_EVENT_SENT: '[STEP-8] => First event sent for validation. Security agent started successfully.',
        DETECTED_BROKEN_CONN: 'Detected Broken Connection. Will Reconnect Now!',
        MAX_WS_RETRY: 'Maximum WS Retry Limit Reached. Unable To Connect To Prevent Web Service!!!',
        EVENT_SENT: 'Event Sent:: ',
        ERROR_WHILE_SEND_EVENT: 'ERROR While Sending Event: {}',
        WS_CONNECTED: '[STEP-4][COMPLETE][WS] Connected To Prevent-web Service',
        SENDING_APPINFO: '[APP_INFO] Sending Application Info To Prevent-web Service: ',
        SENDING_APPINFO_COMPLETE: '[STEP-3][COMPLETE][APP_INFO] Application info sent to Prevent-Web service :',
        APPLY_INSTRUMENTATION: '[STEP-6][BEGIN][instrumentation] Applying Instrumentation',
        AVAIL_DISK: 'Available Disk Space Is: ',
        AVAIL_DISK_ERROR: 'Insufficient Disk Space Available To The Location %s Is : %s',
        OBJ_WRAP_MUST_BE_FUNC: 'original object and wrapper must be functions',
        NO_ORIG_FUNC_TO_WRAP: 'no original function %s to wrap',
        NO_WRAPPER_FUNC: 'no wrapper function',
        ERR_IN_INIT_HOOK: 'Error in initial setup of hook',
        ERR_IN_ONSTART: 'Error in execution onStart Hook',
        ERR_IN_ONFINISH: 'Error in execution onFinish Hook',
        COLLECTOR_SHUT_DOWN: 'Collector Is Shutting Down!!!!'

    }
};
