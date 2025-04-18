/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Pre-Release
 */

module.exports = initialize
const requestManager = require('../../core/request-manager');
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const lodash = require('lodash');
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { NR_CSEC_FUZZ_REQUEST_ID, QUESTION_MARK, EMPTY_STRING, COLON, SLASH } = require('../../core/constants');
const NRCSECTRACINGDATA = 'NR-CSEC-TRACING-DATA';
const DOUBLE_SLASH = '//';
const logger = API.getLogger();
const url = require('url');


/**
 * Entry point undici module instrumentation.
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName) {
  if(API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.ssrf){
    logger.warn('ssrf detection is disabled');
    return;
  }
  logger.info('Instrumenting ' + moduleName);
  fetchHook(shim, mod, "fetch");
  let util = shim.require('./lib/core/util');
  parseOriginHook(shim, util, "parseOrigin")

}
/**
 * Wrapper for util.parseOrigin
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 */
function parseOriginHook(shim, mod, methodName) {
  shim.wrap(mod, methodName, function ClientWrapper(shim, fn) {
    logger.debug(`Instrumenting ${methodName}`);
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrapper() {
      const request = requestManager.getRequest(shim);
      try {
        if (typeof arguments[0] === 'string') {
          let URLObject = new URL(arguments[0]);
          const data = {};
          data.headers = {};
          data.path = URLObject.pathname ? URLObject.pathname : EMPTY_STRING;
          data.protocol = URLObject.protocol ? URLObject.protocol : 'http:';
          data.headers.host = URLObject.host ? URLObject.host : URLObject.hostname;
          shim.interceptedArgs = data;
          if (request) {
            const traceObject = secUtils.getTraceObject(shim);
            const secMetadata = securityMetaData.getSecurityMetaData(request, data, traceObject, secUtils.getExecutionId(), EVENT_TYPE.HTTP_REQUEST, EVENT_CATEGORY.HTTP)
            this.secEvent = API.generateSecEvent(secMetadata);
            API.sendEvent(this.secEvent);
          }
        }
      } catch (error) {

      }
      const result = fn.apply(this, arguments);
      if (result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        API.generateExitEvent(this.secEvent);
        delete this.secEvent
      }
      return result;
    }
  })
}

/**
 * Wrapper to hook undici.fetch()
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} methodName 
 */
function fetchHook(shim, mod, methodName) {
  shim.wrap(mod, methodName, function makeWrapper(shim, fn) {
    logger.debug(`Instrumenting ${methodName}`);
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrapper() {
      const request = requestManager.getRequest(shim);
      try {
        const completeURL = arguments[0];
        const parsedUrl = url.parse(completeURL);
        const data = {};
        data.headers = {};
        data.method = arguments[0].method ? arguments[0].method : EMPTY_STRING;
        data.path = parsedUrl.pathname ? parsedUrl.pathname : parsedUrl.path;
        data.protocol = parsedUrl.protocol;
        data.headers.host = parsedUrl.host ? parsedUrl.host : parsedUrl.hostname;
        data.port = parsedUrl.port ? parsedUrl.port : parsedUrl.port;

        shim.interceptedArgs = data;
        if (request && !lodash.isEmpty(data.headers.host) && !lodash.isEmpty(data.path)) {
          const appUUID = API.getSecAgent().applicationInfo.applicationUUID;
          const traceObject = secUtils.getTraceObject(shim);
          const secMetadata = securityMetaData.getSecurityMetaData(request, data, traceObject, secUtils.getExecutionId(), EVENT_TYPE.HTTP_REQUEST, EVENT_CATEGORY.HTTP)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);

          let traceHeader = EMPTY_STRING;
          if (request.headers['nr-csec-tracing-data']) {
            traceHeader = request.headers['nr-csec-tracing-data'];
          }

          if (arguments[1] instanceof Object) {
            if (arguments[1] && arguments[1].headers && request.headers) {
              arguments[1].headers[NRCSECTRACINGDATA] = traceHeader + appUUID + '/' + this.secEvent.apiId + '/' + this.secEvent.id + ';';
            } else {
              arguments[1].headers = {};
              arguments[1].headers[NRCSECTRACINGDATA] = traceHeader + appUUID + '/' + this.secEvent.apiId + '/' + this.secEvent.id + ';';
            }
            if (request && request.headers[NR_CSEC_FUZZ_REQUEST_ID] && arguments[1].headers) {
              arguments[1].headers[NR_CSEC_FUZZ_REQUEST_ID] = request.headers[NR_CSEC_FUZZ_REQUEST_ID];
            }
          }
        }
      } catch (error) {
        logger.debug("Error while extracting undici fetch args:", error);
      }
      const result = fn.apply(this, arguments);

      if (result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        API.generateExitEvent(this.secEvent);
        delete this.secEvent
      }
      return result;
    }
  })
}

