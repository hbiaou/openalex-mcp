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
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { STRING } = require('../../core/constants');
const securityMetaData = require('../../core/security-metadata');

module.exports = function initialize(shim, express) {
  logger.info("Instrumenting express")
  if (!express || !express.Router) {
    return false
  }

  if (express.Router.use) {
    wrapExpress4(shim, express)
  }
  else if (express.Router.prototype) {
    wrapExpress5(shim, express)
  }
  if(API && API.getNRAgent() && !API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.invalid_file_access){
    expressFileHook(shim, express && express.response, 'download')
    expressFileHook(shim, express && express.response, 'sendFile')
  }
}

/**
 * Wrapper to hook express version 4.x route method
 * @param {*} shim 
 * @param {*} express 
 */
function wrapExpress4(shim, express) {
  shim.wrap(express.Router, 'route', function wrapRoute(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    logger.debug('Instrumenting express.Router.route');
    return function wrappedRoute() {
      try {
        const stakTrace = secUtils.traceElementForRoute();
        const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
        const key = lodash.upperCase(splittedStack[1]) + ATTHERATE + arguments[0];
        routeManager.setRoute(key, splittedStack[0]);
      } catch (error) {

      }
      const route = fn.apply(this, arguments)
      return route;
    }
  })

  //Wrapper to hook process_params method to extract out path param and query params.
  shim.wrap(express.Router, 'process_params', function wrapParam(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    logger.debug('Instrumenting express.Router.process_params')
    return function wrappedParam() {
      extractParams(shim, arguments[2]);
      const route = fn.apply(this, arguments)
      return route
    }
  })
}
/**
 * Utility function to parse request obejct intercepted from express.router.process_params() method hook
 * @param {*} shim 
 * @param {*} req 
 */
function extractParams(shim, req) {
  if (!requestManager.getRequest(shim)) {
    secUtils.addRequestData(shim, req);
  }
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

/**
 * Wrapper for resp.download()
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} fun 
 */
function expressFileHook(shim, mod, fun) {
  shim.wrap(mod, fun, function makeFAWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    logger.debug(`Instrumenting express.response.${fun}`)
    return function FAWrapper() {
      let parameters = Array.prototype.slice.apply(arguments);
      const interceptedArgs = [arguments[0]];
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if (request && typeof arguments[0] === STRING && !lodash.isEmpty(arguments[0])) {
        const traceObject = secUtils.getTraceObject(shim);
        try {
          parameters[0] = path.resolve(parameters[0]);
        } catch (error) {

        }
        let absoluteParameters = [parameters[0]];
        const secMetadata = securityMetaData.getSecurityMetaData(request, absoluteParameters, traceObject, secUtils.getExecutionId(), EVENT_TYPE.FILE_OPERATION, EVENT_CATEGORY.FILE)
        this.secEvent = API.generateSecEvent(secMetadata);
        API.sendEvent(this.secEvent);
      }
      return fn.apply(this, arguments);
    };
  });
}

/**
 * Wrapper to hook express version 5.x route method
 * @param {*} shim 
 * @param {*} express 
 */
function wrapExpress5(shim, express) {
  shim.wrap(express.Router.prototype, 'route', function wrapRoute(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    logger.debug('Instrumenting express.Router.prototype.route');
    return function wrappedRoute() {
      try {
        const stakTrace = secUtils.traceElementForRoute();
        const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
        const key = lodash.upperCase(splittedStack[1]) + ATTHERATE + arguments[0];
        routeManager.setRoute(key, splittedStack[0]);
      } catch (error) {

      }
      const route = fn.apply(this, arguments)
      return route;
    }
  })

}

module.exports.wrapRouter = function wrapExpress5Router(shim, mod) {
  let layer = shim.require('./lib/layer');
  shim.wrap(layer.prototype, 'match', function wrapParam(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    logger.debug('Instrumenting router.layer.match');
    return function wrappedParam() {
      const route = fn.apply(this, arguments);

      try {
        const uri = this.route.path;
        const params = this.params;
        const transaction = shim.tracer.getTransaction();
        if (transaction) {
          let request = requestManager.getRequestFromId(transaction.id);
          if (params && request) {
            Object.keys(params).forEach(function (key) {
              if (params[key]) {
                if (!request.parameterMap[key]) {
                  request.parameterMap[key] = new Array(params[key].toString());
                  requestManager.setRequest(transaction.id, request);
                }
              }
            });
          }
          if (uri && request) {
            request.uri = uri;
            requestManager.setRequest(transaction.id, request);
          }
        }
      } catch (error) {
        logger.debug("Error while getting path params via router module", error);
      }

      return route
    }
  })
}

