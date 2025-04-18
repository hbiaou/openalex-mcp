
/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const AWS_LAMBDA_NODE_EXEC_ENV_IDENTIFIER = /^AWS_Lambda_nodejs.*$/g;
const AWS_EXECUTION_ENV_VAR = 'AWS_EXECUTION_ENV';
const sep = require('path').sep;

module.exports = {

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
    EMPTY_STRING: '',
    COMMA: ',',
    QUESTION_MARK: '?',
    DOUBLE_PIPE: '||',
    DOTDOTSLASH: '../',
    SLASHDOTDOT: '/..',
    UNDEFINED: 'undefined',
    SELF_FD_PATH: '/proc/self/fd/',
    NR_CSEC_FUZZ_REQUEST_ID: 'nr-csec-fuzz-request-id',
    ASTERISK: "*",
    COMMA_SPACE: ", ",
    SEMI_COLON: ';',
    EQUAL: '=',
    SECURE: 'secure',
    HTTPONLY: 'httponly',
    SAMESITE: 'samesite',
    STRICT: 'strict'

};
