/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


'use strict'

/**
 * Express middleware generates traces where middleware are considered siblings
 * (ended on 'next' invocation) and not nested. Middlware are nested below the
 * routers they are mounted to.
 */

const requestManager = require("../../core/request-manager");
const secUtils = require('../../core/sec-utils');
const { ATTHERATE, DOUBLE_DOLLAR } = require('../../core/constants');
const lodash = require('lodash');
const routeManager = require('../../core/route-manager');
const API = require("../../../nr-security-api");
const logger = API.getLogger();

module.exports = function initialize(shim, hapi, moduleName) {
  if (!hapi || !shim) {
    return
  }

  logger.info(`Instrumenting ${moduleName}`);
  // 'Server' and 'server' both point to the same export,
  // but we can't make any assumption about which will be used.
  // Since we wrap the prototype, the second wrap should exit early.
  shim.wrapReturn(hapi, 'server', serverFactoryWrapper)
  shim.wrapReturn(hapi, 'Server', serverFactoryWrapper)
}

function serverFactoryWrapper(shim, fn, fnName, server) {
  serverPostConstructor.call(server, shim)
}

function serverPostConstructor(shim) {
  const proto = Object.getPrototypeOf(this)
  wrapProtoRoute(shim, proto)
}

/**
 * Wrapper for route
 * @param {*} shim 
 * @param {*} proto 
 */
function wrapProtoRoute(shim, proto) {
  shim.wrap(proto, 'route', function wrapRoute(shim, original) {
    logger.debug(`Instrumenting ${proto}.route`);
    return function wrappedRoute() {
      const args = shim.argsToArray.apply(shim, arguments)
      if (!shim.isObject(args[0])) {
        return original.apply(this, args)
      }
      const obj = args[0];
      for (let i = 0; i < obj.length; i++) {
        try {
          const method = lodash.upperCase(obj[i].method);
          const path = obj[i].path;
          const stakTrace = secUtils.traceElementForRoute();
          const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
          const key = method + ATTHERATE + path;
          routeManager.setRoute(key, splittedStack[0]);
        } catch (error) {

        }
        if (obj[i].handler) {
          handlerWrapper(shim, obj[i]);
        }
      }

      return original.apply(this, args)
    }
  })
}

/**
 * Wrapper to hook each handler corresponding to route
 * @param {*} shim 
 * @param {*} mod 
 */
function handlerWrapper(shim, mod) {
  shim.wrap(mod, 'handler', function wrapHandler(shim, original) {
    if (!shim.isFunction(original)) {
      return original
    }
    return function wrappedHandler() {
      extractParams(shim, arguments[0]);
      return original.apply(this, arguments);
    }
  })
}


/**
 * Utility function to parse request obejct intercepted from express.router.process_params() method hook
 * @param {*} shim 
 * @param {*} req 
 */
function extractParams(shim, req) {
  const transaction = shim.tracer.getTransaction();
  if (transaction) {
    let request = requestManager.getRequestFromId(transaction.id);
    if (req.params && request) {
      Object.keys(req.params).forEach(function (key) {
        if (req.params[key]) {
          if (!request.parameterMap[key]) {
            request.parameterMap[key] = new Array(req.params[key].toString());
            requestManager.setRequest(transaction.id, request);
          }
        }
      });
    }
    if (req.query && request) {
      Object.keys(req.query).forEach(function (key) {
        if (req.query[key]) {
          if (!request.parameterMap[key]) {
            request.parameterMap[key] = new Array(req.query[key].toString());
            requestManager.setRequest(transaction.id, request);
          }
        }
      });
    }
    if (req.route && req.route.path && request) {
      request.uri = req.route.path;
      requestManager.setRequest(transaction.id, request);
    }
  }
}
