/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Pre-Release
 */

'use strict'
const requestManager = require("../../core/request-manager");
const API = require("../../../nr-security-api");
const routeManager = require('../../core/route-manager');
const logger = API.getLogger();
const lodash = require('lodash');
const { ATTHERATE, DOUBLE_DOLLAR, EMPTY_STR } = require('../../core/constants');

const semver = require('semver')
const fs = require('fs');
const path = require('path');

module.exports = function initialize(shim, nextjs) {
  const nextVersion = shim.require('./package.json').version
  logger.info("Instrumenting nextjs", nextVersion);

  const nextServer = nextjs.default;
  hookRunAPI(shim, nextServer.prototype, nextVersion);

  //TODO need to update for API endpoints
  try {
    const appRoot = process.env.PWD;
    const searchPath = appRoot + '/.next/server/pages/api';
    const allAPIEndpoints = getAllAPIEndpoints(searchPath);
    logger.debug("allAPIEndpoints:", allAPIEndpoints);
    for (let index = 0; index < allAPIEndpoints.length; index++) {
      const element = allAPIEndpoints[index];
      let key = "*" + ATTHERATE + element;
      routeManager.setRoute(key, EMPTY_STR);
    }
  } catch (error) {
    logger.debug("Error while getting all API end points for next.js", error);
  }


}

/**
 * Wrapper for Server.prototype.runApi
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} nextVersion 
 */
function hookRunAPI(shim, mod, nextVersion) {
  shim.wrap(mod, 'runApi', function wrapRunApi(shim, originalFn) {
    if (!shim.isFunction(originalFn)) {
      return originalFn
    }
    logger.debug("Instrumenting Server.prototype.runApi");
    return function wrappedRunApi() {
      try {
        const { page, params } = extractAttrs(arguments, nextVersion)
        extractParams(shim, page, params);
      } catch (error) {
        logger.debug("Error while processing path paramters");
      }

      return originalFn.apply(this, arguments)
    }
  })
}

/**
 * Extracts the page and params from an API request
 *
 * @param {object} args arguments to runApi
 * @param {string} version next.js version
 * @returns {object} { page, params }
 */
function extractAttrs(args, version) {
  let params
  let page
  if (semver.gte(version, '13.4.13')) {
    const [, , , match] = args
    page = match?.definition?.pathname
    params = { ...match?.params }
  } else {
    ;[, , , params, page] = args
  }

  return { params, page }
}

/**
 * Utility to extract path params
 * @param {*} page 
 * @param {*} params 
 */
function extractParams(shim, page, params) {
  try {
    const transaction = shim.tracer.getTransaction();
    if (transaction) {
      let request = requestManager.getRequestFromId(transaction.id);
      Object.keys(params).forEach(function (key) {
        if (params[key]) {
          if (!request.parameterMap[key]) {
            request.parameterMap[key] = new Array(params[key].toString());
            requestManager.setRequest(transaction.id, request);
          }
        }
      });
      if (request && page) {
        request.uri = page;
        requestManager.setRequest(transaction.id, request);
      }
    }
  } catch (error) {
  }
}


/**
 * Utility to scan pages directory to get all avaible routes
 * @param {*} dir 
 * @returns 
 */
const getAllAPIEndpoints = (dir) => {
  logger.debug("dir is:", dir)
  const apiEndpoints = [];

  const scanDirectory = (currentDir) => {
    logger.debug("currentDir is:", currentDir)
    const files = fs.readdirSync(currentDir);

    files.forEach((file) => {
      const filePath = path.join(currentDir, file);
      const isDirectory = fs.statSync(filePath).isDirectory();

      if (isDirectory) {
        scanDirectory(filePath);
      } else {
        const apiEndpoint = filePath.replace(`${dir}/`, '/api/').replace(/\.js*.*/, '');
        apiEndpoints.push(apiEndpoint);
      }
    });
  };

  scanDirectory(dir);
  return apiEndpoints;
};
