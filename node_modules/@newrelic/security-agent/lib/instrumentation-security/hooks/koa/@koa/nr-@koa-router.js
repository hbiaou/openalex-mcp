/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

module.exports = initialize
const requestManager = require('../../../core/request-manager');
const secUtils = require('../../../core/sec-utils');
const { ATTHERATE, DOUBLE_DOLLAR } = require('../../../core/constants');
const lodash = require('lodash');
const routeManager = require('../../../core/route-manager');
const url = require('url');
const API = require("../../../../nr-security-api");
const logger = API.getLogger();

/**
 * Entry point of koa-router module hook
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName) {
    logger.info(`Instrumenting ${moduleName}`);
    const VerbMethods = ['all', 'delete', 'get', 'head', 'opts', 'post', 'put', 'patch'];

    // RouteMap hooks
    VerbMethods.forEach(function (fun) {
        shim.wrap(mod && mod.prototype, fun, function wrapRoute(shim, fn) {
            if (!shim.isFunction(fn)) {
                return fn
            }
            logger.debug(`Instrumenting ${moduleName}.prototype.${fun}`);
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

    try {
        const layerModule = shim.require("./lib/layer")
        paramHook(shim, layerModule, moduleName);
    } catch (error) {
    }


}
/**
 * Wrapper for params method, to intercept path params and query params 
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function paramHook(shim, mod, moduleName) {
    shim.wrap(mod && mod.prototype, 'params', function wrapMatch(shim, fn) {
        logger.debug(`Instrumenting ${moduleName}.prototype.params`);
        return function wrappedMatch() {
            const transaction = shim.tracer.getTransaction();
            if (transaction) {
                let request = requestManager.getRequestFromId(transaction.id);
                try {
                    const uri = this.path;
                    if (request) {
                        request.uri = uri;
                        requestManager.setRequest(transaction.id, request);
                    }

                } catch (error) {

                }

                const result = fn.apply(this, arguments);
                try {
                    var url_parts = url.parse(request.url, true);
                    // logic to get query param
                    if (url_parts.query) {
                        Object.keys(url_parts.query).forEach(function (key) {
                            if (url_parts.query[key]) {
                                request.parameterMap[key] = new Array(url_parts.query[key].toString());
                            }
                        });
                    }
                    // logic to get path param
                    if (!lodash.isEmpty(result)) {
                        Object.keys(result).forEach(function (key) {
                            if (result[key]) {
                                if (!request.parameterMap[key]) {
                                    request.parameterMap[key] = new Array(result[key].toString());
                                }
                            }
                        });
                    }
                    requestManager.setRequest(transaction.id, request);
                } catch (error) {

                }
                return result;
            }
            else{
                return fn.apply(this,arguments);
            }
           
        }
    })
}
