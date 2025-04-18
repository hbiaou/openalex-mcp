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
const { QUESTIONMARK } = require('../../core/constants');
const API = require("../../../nr-security-api");
const logger = API.getLogger();
const { APPLICATION_JSON } = require('../../core/constants');
let querystring = require('querystring');


module.exports = function initialize(shim, mod) {
  logger.info("Instrumenting graphql");

  shim.wrap(mod, 'execute', function wrapExecute(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn;
    }
    return function wrappedExecute() {
      const transaction = shim.tracer.getTransaction();
      try {
        if (transaction) {
          let request = requestManager.getRequestFromId(transaction.id);
          let customDataType = {};
          //check for query parms
          if (request.headers['x-apollo-operation-name']) {
            const queryString = request.url.split(QUESTIONMARK)[1];
            const parsedQueryString = querystring.parse(queryString);
            let allValues = Object.values(parsedQueryString);
            for (let index = 0; index < allValues.length; index++) {
              const element = allValues[index];
              if (element.startsWith('query')) {
                customDataType['*.query'] = 'GRAPHQL_QUERY';
              }
              if (element.startsWith('variables')) {
                customDataType['*.variables'] = 'GRAPHQL_VARIABLE';
              }
            }
            request.customDataType = customDataType;
            requestManager.setRequest(transaction.id, request);
          }

          //check for body
          if (request.headers['content-type'] === APPLICATION_JSON) {
            const requestBody = JSON.parse(request.body);
            if (requestBody.query) {
              customDataType['*.query'] = 'GRAPHQL_QUERY';
            }
            if (requestBody.variables) {
              customDataType['*.variables'] = 'GRAPHQL_VARIABLE';
            }
            request.customDataType = customDataType;
            requestManager.setRequest(transaction.id, request);
          }
        }

      } catch (error) {
        logger.debug("Error while processing graphql http request", error);
      }

      return fn.apply(this, arguments);
    }
  })
}

