/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

module.exports = initialize
const requestManager = require('../../core/request-manager');
const secUtils = require('../../core/sec-utils');
const { ATTHERATE, DOUBLE_DOLLAR } = require('../../core/constants');
const lodash = require('lodash');
const routeManager = require('../../core/route-manager');
const url = require('url');
const API = require("../../../nr-security-api");
const logger = API.getLogger();

/**
 * Entry point of restify module hook.
 * Wrapper for registryRadix module 
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName) {
    logger.info(`Instrumenting ${moduleName}`);
    try {
        const registryRadix = shim.require("./lib/routerRegistryRadix");

        //routerRadix hook
        shim.wrap(registryRadix && registryRadix.prototype, 'add', function makeWrapper(shim, fn) {
            logger.info(`Instrumenting registryRadix.prototype.add`);
            return function wrapper() {
                if (arguments[0]) {
                    try {
                        const method = lodash.upperCase(arguments[0].method);
                        const path = arguments[0].path;
                        const key = method + ATTHERATE + path;
                        const stakTrace = secUtils.traceElementForRoute();
                        const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
                        routeManager.setRoute(key, splittedStack[0]);
                    } catch (error) {

                    }
                }
                return fn.apply(this, arguments);
            }
        })

        const router = shim.require("./lib/router");

        shim.wrap(router && router.prototype, 'lookup', function lookupWrapper(shim, fn) {
            logger.info(`Instrumenting router.prototype.lookup`);
            return function wrappedLookup() {
                const result = fn.apply(this, arguments);
                extractParams(shim, arguments[0]);
                return result;
            }
        })
    } catch (error) {
    }

}

/**
 * Utilty to extract path params and query params  
 * @param {*} shim 
 * @param {*} req 
 */
function extractParams(shim, req) {
    const transaction = shim.tracer.getTransaction(); 
    if (transaction) {

        let request = requestManager.getRequestFromId(transaction.id);
        if (req.params && request) {
            try {
                Object.keys(req.params).forEach(function (key) {
                    if (req.params[key]) {
                        if (!request.parameterMap[key]) {
                            request.parameterMap[key] = new Array(req.params[key].toString());
                            requestManager.setRequest(transaction.id, request);
                        }
                    }
                });
            } catch (error) {

            }
        }
        if (req.query && request) {
            try {
                const url_parts = url.parse(req.url, true);
                const query = url_parts.query;
                Object.keys(query).forEach(function (key) {
                    if (query[key]) {
                        request.parameterMap[key] = new Array(query[key].toString());
                        requestManager.setRequest(transaction.id, request);
                    }
                });
            } catch (error) {

            }
        }
        if (req.route && req.route.path && request) {
            request.uri = req.route.path;
            requestManager.setRequest(transaction.id, request);
        }
    }
}
