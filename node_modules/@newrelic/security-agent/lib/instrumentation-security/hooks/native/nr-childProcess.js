/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

module.exports = initialize;
const requestManager = require("../../core/request-manager");
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');
const logger = API.getLogger();

function initialize(shim, childProcess, moduleName) {
  if(API && API.getNRAgent() &&  API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.command_injection){
    logger.warn('command_injection detection is disabled');
    return;
  }
  logger.info('Instrumenting child_process');
  execFileHook(shim, childProcess, moduleName);
  spawnHook(shim, childProcess, moduleName);
  spawnSyncHook(shim, process.binding("spawn_sync"), moduleName);
}
/**
 * Wrapper to hook childProcess.execFile() 
 * @param {*} shim 
 * @param {*} childProcess 
 * @param {*} moduleName 
 */
function execFileHook(shim, childProcess, moduleName) {
  shim.wrap(childProcess, "execFile", function makeWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.execFile`);
    return function wrapper() {
      const interceptedArgs = [arguments[0]];
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if (request && arguments[0]) {
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.SYSTEM_COMMAND, EVENT_CATEGORY.SYS)
        const secEvent = API.generateSecEvent(secMetadata);
        API.sendEvent(secEvent);
        if (request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
          callbackHook(shim, arguments, arguments.length - 1, secEvent);
        }

      }

      return fn.apply(this, arguments);
    };
  });
}

/**
 * Function to wrap childProcess.spawnSync()
 * @param {*} shim 
 * @param {*} childProcess 
 * @param {*} moduleName 
 */
function spawnSyncHook(shim, childProcess, moduleName) {
  shim.wrap(childProcess, "spawn", function makeWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.spawnSync`);
    return function wrapper() {
      const interceptedArgs = arguments[0].args;
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if (request) {
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.SYSTEM_COMMAND, EVENT_CATEGORY.SYS)
        this.secEvent = API.generateSecEvent(secMetadata);
        API.sendEvent(this.secEvent);
      }
      const result = fn.apply(this, arguments);
     
      if(result && result.status==0 && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]){
        API.generateExitEvent(this.secEvent);
        delete this.secEvent
      }
      return result;
    };
  });
}

/**
 * Function to wrap childProcess.spawn()
 * @param {*} shim 
 * @param {*} childProcess 
 * @param {*} moduleName 
 */
function spawnHook(shim, childProcess, moduleName) {
  shim.wrap(childProcess, "spawn", function makeWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.spawn`);
    return function wrapper() {
      let param = [];
      param.push(arguments[0]);
      if (arguments[1]) {
        param.push(arguments[1].toString());

      }
      const interceptedArgs = param;
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if (request) {
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.SYSTEM_COMMAND, EVENT_CATEGORY.SYS)
        const secEvent = API.generateSecEvent(secMetadata);
        API.sendEvent(secEvent);
        if (request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
          callbackHook(shim, arguments, arguments.length - 1, secEvent);
        }
      }
      return fn.apply(this, arguments);
    };
  });
}

/**
 * Callback hook to generate exit event
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} fun 
 * @param {*} secEvent 
 */
function callbackHook(shim, mod, fun, secEvent) {
  shim.secEvent = secEvent;
  shim.wrap(mod, fun, function callbackWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn;
    }
    return function wrapper(secEvent) {
      if ((arguments[0] === null || arguments[0] === undefined) && shim.secEvent) {
        API.generateExitEvent(shim.secEvent);
        delete shim.secEvent;
      }
      return fn.apply(this, arguments);
    }
  })
}