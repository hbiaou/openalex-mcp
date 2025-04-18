/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const path = require('path');
const API = require("../../nr-security-api");
const NRAgent = API.getNRAgent();
let AGENT_DIR = path.join(__dirname, '../../');
if(process.platform == 'win32'){
    AGENT_DIR = path.join(__dirname, "..\\..\\..\\");
}
const NR_LIB = '/newrelic/lib';
let LOAD_LIST;
const { IS_LAMBDA_ENV, LAMBDA_RUNTIME_DIR_VAR } = require('./constants');
const LAMBDA_RUNTIME_DIR = process.env[LAMBDA_RUNTIME_DIR_VAR];
const PROMISE_SEPERATOR = '---------------------------------------------';
const ANONYMOUS_FUNCTION = '<anonymous>';
const NODE_MODULES_LITERAL = 'node_modules';
const OPEN_BRACKET = '(';
const CLOSE_BRACKET = ')';
const COLON = ':';
const ACYNC_HOOKS = 'async_hooks.js';
const RUNINASYNCSCOPE = 'runInAsyncScope';

/**
 * Synchronously prints the stack trace from provided trace
 * and extract user script.
 *
 * @param {*} trace
 * @param {*} currentFile
 *
 * @returns {*} detected source info
 */
 function getSourceDetailsFromTrace (trace, currentFile, stakTrace) {
    const info = {};
    let sourceCaptured = false;
    let evalObj;
    let evalFlag = true;
    let getEvalOrigin;
    let isEval = false;
    for (let i = 0; i < trace.length && i < 20; i++) {
        const funcName = trace[i].getFunctionName();
        const fileName = trace[i].getFileName();
        const lineNumber = trace[i].getLineNumber();
        
        if (NRAgent && NRAgent.config.security.detection.rci.enabled && NRAgent.config.security.detection.deserialization.enabled) {
            getEvalOrigin = trace[i].getEvalOrigin();
            isEval = trace[i].isEval();
        }

        let prevMethodName = null;
        if (i > 0 && isEval) {
            const mname = trace[i - 1].getMethodName();
            prevMethodName = mname || trace[i - 1].getFunctionName();
        }

        if (isEval && evalFlag && NRAgent && NRAgent.config.security.detection.rci.enabled && NRAgent.config.security.detection.deserialization.enabled) {
            const serachStr = prevMethodName + OPEN_BRACKET + trace[i - 1].getFileName() + COLON + trace[i - 1].getLineNumber() + CLOSE_BRACKET;
            evalObj = computeTrace(getEvalOrigin, prevMethodName, stakTrace, serachStr);
            evalFlag = false;
        }
        if (fileName && !fileName.includes(AGENT_DIR) && !fileName.includes(NR_LIB) &&
            !fileName.includes(PROMISE_SEPERATOR) &&
            !isLambdaRuntimeFile(fileName)
        ) {
          
            if (!sourceCaptured) {
                info.source = {
                    funcName: prevMethodName || ((funcName) || ANONYMOUS_FUNCTION),
                    fileName: fileName,
                    lineNumber: lineNumber
                };
                sourceCaptured = true;
            }
            if (!fileName.includes(NODE_MODULES_LITERAL) && !LOAD_LIST.includes(fileName) && !fileName.includes('node:') && !fileName.includes(NR_LIB)) {
                info.fileName = fileName;
                info.funcName = ((funcName) || ANONYMOUS_FUNCTION);
                info.lineNumber = lineNumber;
                // break;
            }
        }
    }

    if (!info.fileName && sourceCaptured) {
        info.fileName = info.source.fileName;
        info.funcName = ((info.source.funcName) ? info.source.funcName : ANONYMOUS_FUNCTION);
        info.lineNumber = info.source.lineNumber;
    }
    if (evalObj) {
        info.evalObj = evalObj;
    }
    return info;
}


function isLambdaRuntimeFile (fileName) {
    return IS_LAMBDA_ENV && fileName.includes(LAMBDA_RUNTIME_DIR);
}

/**
 * Sets the load list.
 *
 * @param {*} list
 */
 const setLoadList = list => {
    LOAD_LIST = list;
};


function computeTrace (traceLine, apiCall, stakTrace, serachStr) {
    const regex = /^(?:\s*at )?(?:(new) )?(?:(.*?) \()?(?:eval at ([^ ]+) \((.+?):(\d+):(\d+)\), )?(?:(.+?):(\d+):(\d+)|(native))(\)?)$/;
    const evalObj = {};
    try {
        const line = traceLine.match(regex);
        evalObj.apiCall = apiCall;
        if (line) {
            evalObj.funcName = line[2];
            evalObj.fileName = line[7];
            evalObj.lineNumber = line[8];
            const indexUpTo = stakTrace.indexOf(serachStr);
            const apicalls = stakTrace.slice(0, indexUpTo + 1);
            if (indexUpTo == -1) {
                apicalls.push(serachStr);
            }
            evalObj.invokedCalls = apicalls;
        }
    } catch (error) {
    }

    return evalObj;
}

module.exports = {
    getSourceDetailsFromTrace,
    setLoadList
}