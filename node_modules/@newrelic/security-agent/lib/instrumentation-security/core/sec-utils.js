/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const stackTraceModule = require('./stack-trace');
const path = require('path');
const secTrace = require('./sec-trace');
const requestManager = require('./request-manager');
const routeManager = require('./route-manager');
const async_hooks = require('async_hooks');
const crypto = require('crypto');

let AGENT_DIR = path.join(__dirname, '../../');

if (process.platform == 'win32') {
    AGENT_DIR = path.join(__dirname, "..\\..\\");
}
const NR_LIB = '/newrelic/lib';

const ANONYMOUS_FUNCTION = '<anonymous>';
const OPEN_PARANTHESIS = '(';
const COLON = ':';
const CLOSE_PARANTHESIS = ')';
const SPACE_CHARACTER = ' ';
const REPL_MODULE = 'repl';
const NATIVES_MODULE = 'natives';
const ASYNC_HOOKS_MODULE = 'async_hooks';
const JS_EXTENSION = '.js';
const ACYNC_HOOKS = 'async_hooks.js';
const RUNINASYNCSCOPE = 'runInAsyncScope';
const NODE_MODULE = 'node_modules';
const DOUBLE_DOLLAR = '$$';
const ATTHERATE = '@';

const API = require("../../nr-security-api");
const logger = API.getLogger();

createSkipList();
const fs = require('fs');
const cp = require('child_process');
const requestIp = require('request-ip');
const URL = require('url');
const { EMPTY_STR } = require('./constants');

/**
 * Creates a list of loaded internal modules,
 * which is used in sec-trace and by module-tracker.
 *
 * @returns {Array} loadList
 */
function createSkipList() {
    let loadList = [];
    process.moduleLoadList.forEach(function (loadString) {
        loadList.push(loadString.split(SPACE_CHARACTER).pop());
    });
    loadList = loadList.concat(require(REPL_MODULE)._builtinLibs);

    loadList = loadList.concat(Object.keys(process.binding(NATIVES_MODULE)));
    for (let i = 0; i < loadList.length; i++) {
        loadList[i] += JS_EXTENSION;
    }
    require('./sec-trace').setLoadList(loadList);
    return loadList;
}


function getTraceObject(shim) {
    const trace = stackTraceModule.get();
    const traceLength = 10;
    const stkTrace = [];
    for (let i = 0; i < trace.length && stkTrace.length < traceLength; i++) {
        const funcName = trace[i].getFunctionName();
        const fileName = trace[i].getFileName();
        const lineNumber = trace[i].getLineNumber();

        if (fileName && !fileName.includes(AGENT_DIR) && !fileName.includes(NR_LIB)) {
            const functionName = funcName || ANONYMOUS_FUNCTION;
            const resTrace = functionName + OPEN_PARANTHESIS + fileName + COLON + lineNumber + CLOSE_PARANTHESIS;
            stkTrace.push(resTrace);
        }
    }
    const request = requestManager.getRequest(shim);
    const key = request.method + ATTHERATE + request.uri;
    const routeFile = routeManager.getRoute(key);
    if (routeFile) {
        stkTrace.push(routeFile);
    }
    const sourceDetails = secTrace.getSourceDetailsFromTrace(trace, __filename, stkTrace);
    const traceObject = {
        sourceDetails: sourceDetails,
        stacktrace: stkTrace
    }
    return traceObject;
}

function getTraceObjectFallback(request) {
    const trace = stackTraceModule.get();
    const traceLength = 10;
    const stkTrace = [];
    for (let i = 0; i < trace.length && stkTrace.length < traceLength; i++) {
        const funcName = trace[i].getFunctionName();
        const fileName = trace[i].getFileName();
        const lineNumber = trace[i].getLineNumber();

        if (fileName && !fileName.includes(AGENT_DIR) && !fileName.includes(NR_LIB)) {
            const functionName = funcName || ANONYMOUS_FUNCTION;
            const resTrace = functionName + OPEN_PARANTHESIS + fileName + COLON + lineNumber + CLOSE_PARANTHESIS;
            stkTrace.push(resTrace);
        }
    }
    const key = request.method + ATTHERATE + request.uri;
    const routeFile = routeManager.getRoute(key);
    if (routeFile) {
        stkTrace.push(routeFile);
    }
    const sourceDetails = secTrace.getSourceDetailsFromTrace(trace, __filename, stkTrace);
    const traceObject = {
        sourceDetails: sourceDetails,
        stacktrace: stkTrace
    }
    return traceObject;
}


function traceElementForRoute() {
    const stkTrace = [];
    const trace = stackTraceModule.get();
    let methodName = null;

    for (let i = 0; i <= trace.length - 1; i++) {
        const funcName = trace[i].getFunctionName();
        const fileName = trace[i].getFileName();
        const lineNumber = trace[i].getLineNumber();
        if (i > 0) {
            methodName = trace[i - 1].getMethodName();
        }

        if (fileName && !fileName.includes(AGENT_DIR) && fileName !== ACYNC_HOOKS && funcName !== RUNINASYNCSCOPE && !fileName.includes(NODE_MODULE)) {
            const functionName = methodName || funcName || ANONYMOUS_FUNCTION;
            const resTrace = functionName + OPEN_PARANTHESIS + fileName + COLON + lineNumber + CLOSE_PARANTHESIS + DOUBLE_DOLLAR + methodName;
            stkTrace.push(resTrace);
        }
    }
    return stkTrace;
}

function getExecutionId() {
    return async_hooks.executionAsyncId();
}

function createPathIfNotExist(dir) {
    try {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, 770, { recursive: true });
            logger.info(dir + ' Created');
            fs.chmodSync(dir, 0o770);
        } else {
            fs.chmodSync(dir, 0o770);
            logger.debug(dir + ' Already Exists');
        }
    } catch (error) {
        logger.debug(dir + ' Not Created', error);
    }
}

/**
 * Utility function to add request data in a Map
 * @param {*} shim 
 * @param {*} request 
 */
function addRequestData(shim, request) {
    try {
        const data = Object.assign({});
        const transaction = shim.tracer.getTransaction();
        if (transaction) {
            data.protocol = (request.connection && request.connection.encrypted) ? 'https' : 'http';
            data.body = null;
            data.headers = request.headers;
            data.url = request.url;
            data.method = request.method;
            data.httpVersion = request.httpVersion;
            data.serverPort = transaction.port;
            data.contextPath = '/';
            const queryObject = URL.parse(request.url, true).query;
            data.parameterMap = {};
            if (queryObject) {
                Object.keys(queryObject).forEach(function (key) {
                    if (queryObject[key]) {
                        if (!data.parameterMap[key]) {
                            data.parameterMap[key] = new Array(queryObject[key].toString());
                        }
                    }
                });
            }
            data.clientIP = requestIp.getClientIp(request);
            data.dataTruncated = false;
            const transactionId = transaction.id;
            const storedRequest = requestManager.getRequestFromId(transactionId);
            if (storedRequest && storedRequest.uri) {
                data.uri = storedRequest.uri;
                data.parameterMap = storedRequest.parameterMap;
            }
            requestManager.setRequest(transactionId, data);
            if (shim.agent.getLinkingMetadata()) {
                let linkingMetadata = shim.agent.getLinkingMetadata();
                if (linkingMetadata['trace.id']) {
                    let traceId = linkingMetadata['trace.id'];
                    requestManager.setRequest(traceId, data)
                }
            }
        }
    } catch (error) {
        logger.debug("Error while preparing incoming request:", error);
    }
}

function decryptData(encryptedData) {
    let decryptedData = EMPTY_STR;
    try {

        const linkingMetadata = API.newrelic.getLinkingMetadata();
        let entityGuid = linkingMetadata['entity.guid'];
        let password = entityGuid;
        let salt = password.slice(0, 16);
        //derive key
        const key = crypto.pbkdf2Sync(password, salt, 1024, 32, 'sha1');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
        let decrypted = decipher.update(encryptedData, 'hex');
        decrypted += decipher.final();
        decryptedData = decrypted.slice(16, decrypted.length);
    } catch (error) {
        logger.debug("Error while decrypting the data:", error);
    }
    return decryptedData;

}

function hashVerifier(decryptedData, hashFromSE) {
    let flag = false;
    try {
        const hash = crypto.createHash('sha256'); // Create a new hash object
        hash.update(decryptedData); // Write data to the hash object
        let calculatedSHA256Hash = hash.digest('hex');
        if (calculatedSHA256Hash === hashFromSE) {
            flag = true;
        }
    } catch (error) {
        logger.debug("Error while calculating SHA256 of decrypted data:", error);
    }

    return flag;

}


module.exports = {
    getTraceObject,
    traceElementForRoute,
    getExecutionId,
    createPathIfNotExist,
    getTraceObjectFallback,
    addRequestData,
    decryptData,
    hashVerifier
}
