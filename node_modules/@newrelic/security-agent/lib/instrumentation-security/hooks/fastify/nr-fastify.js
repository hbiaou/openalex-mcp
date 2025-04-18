/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict'
const requestManager = require("../../core/request-manager");
const secUtils = require('../../core/sec-utils');
const { ATTHERATE, DOUBLE_DOLLAR } = require('../../core/constants');
const lodash = require('lodash');
const routeManager = require('../../core/route-manager');
const semver = require('semver')
const API = require("../../../nr-security-api");
const logger = API.getLogger();


/**
 * Sets up fastify route handler
 *
 * Fastify's onRoute hook will fire whenever
 * a route is registered.  This is the most straight
 * forward way to get at a fastify route definition.
 * Not only are we _not_ relying on private implementations
 * that could change, fastify is pretty good about protecting
 * those private implementations from access, and getting
 * at them would require a lot of gymnastics and hard to
 * maintain code
 *
 * @param shim
 * @param fastify
 */
const setupRouteHandler = (shim, fastify, moduleName) => {
  logger.info("Instrumenting Fastify")

  const VerbMethods = ['all', 'delete', 'get', 'head', 'post', 'put', 'patch', 'options'];
  //for routeMap
  VerbMethods.forEach(function (fun) {
    shim.wrap(fastify, fun, function wrapRoute(shim, fn) {
      if (!shim.isFunction(fn)) {
        return fn
      }
      logger.debug(`Instrumenting ${moduleName}.${fun}`);
      return function wrappedRoute() {
        try {
          const stakTrace = secUtils.traceElementForRoute();
          const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
          const key = lodash.upperCase(splittedStack[1]) + ATTHERATE + arguments[0];
          routeManager.setRoute(key, splittedStack[0]);
        } catch (error) {
        }
        const route = fn.apply(this, arguments);
        return route;
      }
    })
  });

  fastify.addHook('onRequest', async (request) => {
    if (!requestManager.getRequest(shim)) {
      secUtils.addRequestData(shim, request);
    }
    extractParams(shim, request);
  })

}


module.exports = function initialize(shim, fastify, moduleName) {

  const fastifyVersion = shim.require('./package.json').version
  const isv3Plus = semver.satisfies(fastifyVersion, '>=3.0.0')

  /**
   * Fastify exports a function, so we need to use wrapExport
   */
  const wrappedExport = shim.wrapExport(fastify, function wrapFastifyModule(shim, fn) {
    return function wrappedFastifyModule() {
      // call original function get get fastify object (which is singleton-ish)
      const fastifyForWrapping = fn.apply(this, arguments)

      setupRouteHandler(shim, fastifyForWrapping, moduleName)

      return fastifyForWrapping
    }
  })

  if (isv3Plus) {
    setupExports(fastify, wrappedExport)
  }
}




/**
 * module.exports = fastify
 * module.exports.fastify = fastify
 * module.exports.default = fastify
 *
 * @param original
 * @param wrappedExport
 */
function setupExports(original, wrappedExport) {
  wrappedExport.fastify = original.fastify

  if (original.fastify) {
    wrappedExport.fastify = wrappedExport
  }

  if (original.default) {
    wrappedExport.default = wrappedExport
  }
}

/**
 * Utility to parse request object to get path params and query params
 * @param {*} shim 
 * @param {*} req 
 */
function extractParams(shim, req) {
  try {
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
      const txInfo = lodash.get(req, Object.getOwnPropertySymbols(req).find(symbol => symbol.toString() === 'Symbol(fastify.context)'));
      if (request && txInfo && txInfo.config && txInfo.config.url) {
        request.uri = txInfo.config.url;
        requestManager.setRequest(transaction.id, request);
      }
    }
  } catch (error) {
  }

}
