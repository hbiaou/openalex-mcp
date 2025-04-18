/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


'use strict'

const requestManager = require("../../core/request-manager");
const secUtils = require('../../core/sec-utils');
const { ATTHERATE, DOUBLE_DOLLAR, COLON } = require('../../core/constants');
const lodash = require('lodash');
const routeManager = require('../../core/route-manager');
const API = require("../../../nr-security-api");
const logger = API.getLogger();

module.exports = function initialize(shim, director) {
  const proto = director.Router.prototype

  shim.wrap(proto, 'insert', function wrapParam(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedParam() {
      this.routeMethod = arguments[0]
      return fn.apply(this, arguments);
    }
  })



  shim.wrap(proto, 'mount', function wrapMount(shim, mount) {
    if (!shim.isFunction(mount)) {
      return mount
    }
    return function wrappedMount(routes) {
      shim.wrap(routes, director.http.methods, function wrapRoute(shim, route) {
        if (!shim.isFunction(route)) {
          return route
        }
        return function wrappedRoute() {
          extractParams(shim, arguments);
          return route.apply(this, arguments);
        }
      })

      if (arguments[1]) {
        try {
          const method = this.routeMethod ? this.routeMethod : Object.keys(arguments[0])[0];
          const path = "/" + arguments[1].join('/')
          const stakTrace = secUtils.traceElementForRoute();
          const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
          const key = lodash.upperCase(method) + ATTHERATE + path;
          routeManager.setRoute(key, splittedStack[0]);
          if (path.includes(COLON)) {
            const dummyKey = key.split(COLON)[0] + ":param_input";
            routeManager.setRoute(dummyKey, splittedStack[0]);
          }
        } catch (error) {
          logger.debug("Error in intercepting routes", error);
        }
      }
      return mount.apply(this, arguments);
    }
  })
}

/**
 * Utility function to prepare parameterMap
 * @param {*} shim 
 * @param {*} params 
 */
function extractParams(shim, params) {
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
   
    if (request) {
      let uri = request.url.split("?")[0];
      const param = Object.values(params)[0];
      if (uri.includes(param)) {
        uri = lodash.replace(uri, param, ':param_input');
        request.uri  = uri;
        requestManager.setRequest(transaction.id, request);
      }
    }
  }
}
