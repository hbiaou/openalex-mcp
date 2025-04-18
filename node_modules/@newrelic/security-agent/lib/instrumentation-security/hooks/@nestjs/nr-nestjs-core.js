/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict'

const secUtils = require('../../core/sec-utils');
const { ATTHERATE, DOUBLE_DOLLAR, EMPTY_STR } = require('../../core/constants');
const routeManager = require('../../core/route-manager');
const API = require("../../../nr-security-api");
const logger = API.getLogger();
const semver = require('semver')

const RequestMethods = {
  "0": "GET",
  "1": "POST",
  "2": "PUT",
  "3": "DELETE",
  "4": "PATCH",
  "5": "ALL",
  "6": "OPTIONS",
  "7": "HEAD",
  "8": "SEARCH",
}

module.exports = function initialize(shim) {
  const nestJsVersion = shim.require('./package.json').version
  logger.info("Instrumenting nestjs", nestJsVersion)
  if (semver.lt(nestJsVersion, '8.0.0')) {
    logger.debug(
      `Not instrumenting Nest.js version ${nestJsVersion}; minimum instrumentable version is 8.0.0`
    )
    return
  }

  const routerExplorer = shim.require("./router/router-explorer").RouterExplorer;

  shim.wrap(routerExplorer.prototype, 'applyCallbackToRouter', function wrapApplyCallbackToRouter(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    logger.debug(`Instrumenting routerExplorer.prototype.applyCallbackToRouter`)
    return function wrappedApplyCallbackToRouter() {
      try {
        const stakTrace = secUtils.traceElementForRoute();
        const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
        const verb = RequestMethods[arguments[1].requestMethod];
        const path = (arguments[4].ctrlPath) + (arguments[1].path[0] == '/' ? EMPTY_STR : arguments[1].path[0]);
        const key = verb + ATTHERATE + path;
        routeManager.setRoute(key, splittedStack[0]);
      } catch (error) {
      }
      return fn.apply(this, arguments);
    }
  })

}





