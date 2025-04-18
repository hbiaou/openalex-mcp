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
 * Entry point for xpath module hook
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName){
  if(API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.xpath_injection){
    logger.warn('xpath_injection detection is disabled');
    return;
  }
 logger.info('Instrumenting '+ moduleName)

  if(moduleName==='xpath'){
    xpathHooks(shim, mod, 'evaluate', moduleName);
    xpathHooks(shim, mod, 'selectWithResolver', moduleName);
    xpathHooks(shim, mod, 'useNamespaces', moduleName);
  }
  else if(moduleName==='xpath.js'){
    wrappedXPathDotJS(shim, mod, moduleName);
  }
  
}
/**
 * wrapper to hook xpath module
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 * @param {*} moduleName 
 */
function xpathHooks(shim, mod, methodName, moduleName){
    shim.wrap(mod, methodName, function makeWrapper(shim,fn){
      logger.debug(`Instrumenting ${moduleName}.${methodName}`);
        return function wrapper(){
          const interceptedArgs = [arguments[0]];
          shim.interceptedArgs = interceptedArgs;
          const request = requestManager.getRequest(shim);
          if(request){
            const traceObject = secUtils.getTraceObject(shim);
            const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.XPATH, EVENT_CATEGORY.XPATH)
            const secEvent =  API.generateSecEvent(secMetadata);
            this.secEvent = secEvent;
            API.sendEvent(this.secEvent);
          }
          const result = fn.apply(this, arguments);
     
          if(result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]){
            API.generateExitEvent(this.secEvent);
            delete this.secEvent
          }
          return result;
        }  
    })   
}

/**
 * Function Wrapper for xpath.js module
 * @param {*} shim 
 * @param {*} mod 
 */
function wrappedXPathDotJS(shim, mod, moduleName){
  const wrappedExport = shim.wrapExport(mod, function wrapXpathJSModule(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}`);
    return function wrappedXpathJSModule() {
      const interceptedArgs = [arguments[1]];
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if(request){
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.XPATH, EVENT_CATEGORY.XPATH)
        const secEvent =  API.generateSecEvent(secMetadata);
        this.secEvent = secEvent;
        API.sendEvent(this.secEvent);
      }
      const xpathJSForWrapping = fn.apply(this, arguments);
      if(xpathJSForWrapping && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]){
        API.generateExitEvent(this.secEvent);
        delete this.secEvent
      }
      return xpathJSForWrapping
    }
  })
}
