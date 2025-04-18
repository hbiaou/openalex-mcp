/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


'use strict'

const requestManager = require('../../core/request-manager');
const secUtils = require('../../core/sec-utils');
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const logger = API.getLogger();
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');

module.exports = function initialize(shim, pgsql, moduleName) {
  if(API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.sql_injection){
    logger.warn('sql_injection detection is disabled');
    return;
  }
  logger.info('Instrumenting '+ moduleName)
  // allows for native wrapping to not happen if not necessary
  // when env var is true
  if (process.env.NODE_PG_FORCE_NATIVE) {
    return instrumentPGNative(pgsql)
  }

  // wrapping for native
  function instrumentPGNative(pg) {
    shim.wrapReturn(pg, 'Client', clientFactoryWrapper)
    shim.wrapClass(pg, 'Pool', { post: poolPostConstructor, es6: true })
  }

  function poolPostConstructor(shim) {
    if (!shim.isWrapped(this.Client)) {
      shim.wrapClass(this, 'Client', clientPostConstructor)
    }
  }

  function clientFactoryWrapper(shim, fn, fnName, client) {
    clientPostConstructor.call(client, shim)
  }

  function clientPostConstructor(shim) {
    queryHook(shim, this, 'query');
  }

  // The pg module defines "native" getter which sets up the native client lazily
  // (only when called).  We replace the getter, so that we can instrument the native
  // client.  The original getter replaces itself with the instance of the native
  // client, so only instrument if the getter exists (otherwise assume already
  // instrumented).
  const origGetter = pgsql.__lookupGetter__('native')
  if (origGetter) {
    delete pgsql.native
    pgsql.__defineGetter__('native', function getNative() {
      const temp = origGetter()
      if (temp != null) {
        instrumentPGNative(temp)
      }
      return temp
    })
  }

  queryHook(shim, pgsql && pgsql.Client && pgsql.Client.prototype, 'query');
}



function queryHook(shim, mod, method){
  shim.wrap(mod, method, function makeQueryWrapper(shim, fn){
    logger.debug(`Instrumenting pg.${method}`);
      return function queryWrapper(){
          const request = requestManager.getRequest(shim);
          const sqlArgs = [];
            if (typeof arguments[0] === 'object') {
                if ((arguments[0] && arguments[0].constructor && arguments[0].constructor.name == 'Cursor') || (arguments[0] && arguments[0].text && arguments[0].values)) {
                    sqlArgs.push(arguments[0].text);
                    if (Array.isArray(arguments[0].values)) {
                        sqlArgs.push(arguments[0].values);
                    }
                } else if (arguments[0] && arguments[0].constructor && arguments[0].constructor.name == 'QueryStream' && arguments[0].cursor) {
                    sqlArgs.push(arguments[0].cursor.text);
                    if (Array.isArray(arguments[0].cursor.values)) {
                        sqlArgs.push(arguments[0].cursor.values);
                    }
                }
                else if(arguments[0] && arguments[0].text){
                  sqlArgs.push(arguments[0].text);
                }
            } else {
                for (let i = 0; i < arguments.length; i++) {
                    if (typeof arguments[i] !== 'function') {
                        sqlArgs.push(arguments[i]);
                    }
                }
            }
            shim.interceptedArgs = sqlArgs;
          if (request) {
            const traceObject =  secUtils.getTraceObject(shim);
            const secMetadata = securityMetaData.getSecurityMetaData(request, sqlArgs, traceObject, secUtils.getExecutionId(), EVENT_TYPE.DB_COMMAND, EVENT_CATEGORY.POSTGRES)
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