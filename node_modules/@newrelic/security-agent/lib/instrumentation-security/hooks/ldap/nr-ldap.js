/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

module.exports = initialize
const requestManager = require('../../core/request-manager');
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');
const logger = API.getLogger();

/**
 * Entry point of ldapjs and ldapts module hook
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName){
  if(API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.ldap_injection){
    logger.warn('ldap_injection detection is disabled');
    return;
  }
  logger.info('Instrumenting '+ moduleName )

  if(moduleName==='ldapjs' || moduleName==='ldapts'){
    ldapHooks(shim, mod && mod.Client && mod.Client.prototype, 'search', moduleName);
  }
  
}
/**
 * wrapper to hook ldapjs and ldapts module
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 * @param {*} moduleName 
 */
function ldapHooks(shim, mod, methodName, moduleName){
    shim.wrap(mod, methodName, function makeWrapper(shim,fn){
      logger.debug(`Instrumenting ${moduleName}.${methodName}`);
        return function wrapper(){
          const param = {};
          param.name = arguments[0];
          param.filter = arguments[1].filter;

          const interceptedArgs = [param];
          shim.interceptedArgs = interceptedArgs;
          const request = requestManager.getRequest(shim);
          if(request){
            const traceObject = secUtils.getTraceObject(shim);
            const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.LDAP, EVENT_CATEGORY.LDAP)
            const secEvent =  API.generateSecEvent(secMetadata);
            API.sendEvent(secEvent);
            if (request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
              callbackHook(shim, arguments, arguments.length - 1, secEvent);
            }
          }
            return fn.apply(this, arguments);
        }  
    })   
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
    return function wrapper() {
      if ((arguments[0] === null || arguments[0] === undefined) && shim.secEvent) {
        API.generateExitEvent(shim.secEvent);
        delete shim.secEvent;
      }
      return fn.apply(this, arguments);
    }
  })
}