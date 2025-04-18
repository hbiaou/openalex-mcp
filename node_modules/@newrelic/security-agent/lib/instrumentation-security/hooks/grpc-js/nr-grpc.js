/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Pre-Release
 */


const requestManager = require("../../core/request-manager");
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { NR_CSEC_FUZZ_REQUEST_ID, DOUBLE_DOLLAR, ATTHERATE, ASTERISK } = require('../../core/constants');
const logger = API.getLogger();
const semver = require('semver');
const grpcutils = require('../../core/grpc-utils');
const routeManager = require('../../core/route-manager');
let serverAddress;
const ExceptionReporting = require('../../../nr-security-agent/lib/core/ExceptionReporting');
const responseErrorSet = new Set([2, 12, 13, 14, 15])



module.exports.initialize = function initialize(shim, grpc, moduleName) {
  logger.info('Instrumenting grpc', moduleName);
  const grpcVersion = shim.require('./package.json').version;
  logger.debug("grpc version:", grpcVersion);

  if (semver.lt(grpcVersion, '1.4.0')) {
    logger.warn('gRPC server-side instrumentation only supported on grpc-js >=1.4.0')
    return
  }

  if (semver.gte(grpcVersion, '1.8.0')) {
    const resolvingCall = shim.require('./build/src/resolving-call')
    shim.wrap(resolvingCall.ResolvingCall.prototype, 'start', wrapStart)
  } else {
    const callStream = shim.require('./build/src/call-stream')
    shim.wrap(callStream.Http2CallStream.prototype, 'start', wrapStart)
  }

  const server = shim.require('./build/src/server')
  shim.wrap(server.Server.prototype, 'bindAsync', bindAsyncWrapper)
  shim.wrap(server.Server.prototype, 'register', wrapRegister)

  //get all service
  shim.wrap(server.Server.prototype, 'addService', wrapAddService);

  //load package definition
  const makeClient = shim.require('./build/src/make-client');
  shim.wrap(makeClient, 'loadPackageDefinition', wrapLoadPackageDefinition);

}

module.exports.wrapStartResolve = function wrappedStartResolve(shim, resolvingCall) {
  shim.wrap(resolvingCall.ResolvingCall.prototype, 'start', wrapStart)
}

module.exports.wrapStartCall = function wrappedClient(shim, callStream) {
  shim.wrap(callStream.Http2CallStream.prototype, 'start', wrapStart)
}

/**
 * Wrapper for error collection
 * @param {*} shim 
 * @param {*} call 
 */
module.exports.wrapCall = function wrappedCall(shim, call) {
  shim.wrap(call, 'callErrorFromStatus', function wrapCallErrorFromStatus(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedCallErrorFromStatus() {
      const errRes = fn.apply(this, arguments);
      try {
        let error = new Error(errRes.message);
        error.stack = errRes.stack;
        const request = requestManager.getRequest(shim);
        if (request) {
          ExceptionReporting.generate5xxReportingEvent(error, request);
        }
      } catch (error) {
      }

      return errRes;
    }
  })
}

module.exports.wrapServer = function wrappedServer(shim, server) {
  const grpcVersion = shim.require('./package.json').version
  logger.info("Instrumenting @grpc/grpc-js", grpcVersion)
  if (semver.lt(grpcVersion, '1.4.0')) {
    logger.warn('gRPC server-side instrumentation only supported on grpc-js >=1.4.0')
    return
  }

  shim.wrap(server.Server.prototype, 'register', wrapRegister)
  shim.wrap(server.Server.prototype, 'bindAsync', bindAsyncWrapper)
  //get all service
  shim.wrap(server.Server.prototype, 'addService', wrapAddService);
}

module.exports.wrapMakeClient = function wrapMakeClient(shim, makeClient) {
  shim.wrap(makeClient, 'loadPackageDefinition', wrapLoadPackageDefinition);
}


/**
 * Instruments grpc-js client by intercepting the function that
 * initiates client requests. This handles all four types of client
 * invocations: unary, client-streaming, server-streaming, and
 * bidirectional streaming.
 *
 * @param {object} shim the generic shim to instrument with
 * @param {Function} original the original function
 * @returns {Function} the instrumented function
 */
function wrapStart(shim, original) {
  if (!shim.isFunction(original)) {
    return original
  }
  return function wrappedStart() {
    const channel = this.channel;
    const authorityName = (channel.target && channel.target.path) || channel.getDefaultAuthority;
    // in 1.8.0 this changed from methodName to method
    const method = this.methodName || this.method;
    const protocol = 'grpc:';
    const url = `${protocol}//${authorityName}${method}`;
    logger.debug("grpc url is:", url)
    const request = requestManager.getRequest(shim);
    let urlObj = {
      "headers":
      {
        "host": authorityName
      },
      "method": method,
      "path": method,
      "protocol": protocol,
    }

    if (request) {
      const traceObject = secUtils.getTraceObject(shim);
      const secMetadata = securityMetaData.getSecurityMetaData(request, urlObj, traceObject, secUtils.getExecutionId(), EVENT_TYPE.HTTP_REQUEST, EVENT_CATEGORY.HTTP)
      const secEvent = API.generateSecEvent(secMetadata);
      API.sendEvent(secEvent);
    }

    const res = original.apply(this, arguments);
    return res;
  }
}


/**
 * Wrapper for addService method
 * @param {*} shim 
 * @param {*} original 
 * @returns 
 */
function wrapAddService(shim, original) {
  if (!shim.isFunction(original)) {
    return original
  }
  return function wrappedbindAsync() {
    try {
      const stakTrace = secUtils.traceElementForRoute();
      const splittedStack = stakTrace[0].split(DOUBLE_DOLLAR);
      let serviceValues = Object.values(arguments[0]);
      for (const [key, value] of Object.entries(serviceValues)) {
        const routeKey = ASTERISK + ATTHERATE + value.path;
        let finalHandler = value.originalName + ATTHERATE + splittedStack[0];
        routeManager.setRoute(routeKey, finalHandler);
      }
    } catch (error) {
    }
    const result = original.apply(this, arguments);
    return result;
  }
}

/**
 * wrapper for loadPackageDefinition method
 * @param {*} shim 
 * @param {*} original 
 * @returns 
 */
function wrapLoadPackageDefinition(shim, original) {
  if (!shim.isFunction(original)) {
    return original
  }
  return function wrappedbindAsync() {
    let serviceObject = arguments[0];
    const result = original.apply(this, arguments);
    iterateNestedObjectForServiceLookup(result, serviceObject);
    return result;
  }
}




function bindAsyncWrapper(shim, original) {
  if (!shim.isFunction(original)) {
    return original
  }
  return function wrappedbindAsync() {
    serverAddress = arguments[0];
    shim.grpcServerAddress = serverAddress;
    try {
      const splittedData = serverAddress.split(":");
      serverPort = splittedData[1];
      shim.serverPort = parseInt(serverPort);
    } catch (error) {

    }
    const result = original.apply(this, arguments);
    return result;
  }
}



/**
 * Instruments the grpc-js server by intercepting the moment when
 * server methods are registered from the method implementations
 * provided to grpc-js. This handles all four types of server
 * invocations: unary, client-streaming, server-streaming, and
 * bidirectional streaming.
 *
 * @param {object} shim the web shim to instrument with
 * @param {Function} original the original function
 * @returns {Function} the instrumented function
 */
function wrapRegister(shim, original) {
  if (!shim.isFunction(original)) {
    return original
  }
  return function wrappedRegister() {
    wrapHandler(shim, arguments, '1');
    const result = original.apply(this, arguments);
    return result;
  }
}


/**
 * Wrapper to hook handler function
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} method 
 */
function wrapHandler(shim, mod, method) {
  shim.wrap(mod, method, function wrapHandler(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedHandler() {
      const type = this.type;
      const path = this.path;
      wrapCallback(shim, arguments, '1');
      addRequestData(shim, type, path, arguments[0]);
      const result = fn.apply(this, arguments);
      return result;

    }
  })
}

/**
 * Wrapper to hook callback response
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} method 
 */
function wrapCallback(shim, mod, method) {
  shim.wrap(mod, method, function wrapCallback(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedCallback() {
      const response = arguments[1];
      try {
        const request = requestManager.getRequest(shim);
        if (arguments[0]) {
          if (arguments[0].details && request) {
            ExceptionReporting.generateExceptionReportingEvent(arguments[0].details, request);
          }

          if (arguments[0].code && responseErrorSet.has(arguments[0].code) && request) {
            let responseCode = arguments[0].code
            ExceptionReporting.generate5xxReportingEvent(null, request, responseCode);
          }
        }
      } catch (error) {

      }
      const result = fn.apply(this, arguments);
      return result;

    }
  })
}

/**
 * Utility function to add grpc request data in request map
 * @param {*} shim 
 * @param {*} type 
 * @param {*} path 
 * @param {*} args 
 */
function addRequestData(shim, type, path, args) {
  const data = Object.assign({});
  try {
    const transaction = shim.tracer.getTransaction();
    if (transaction) {
      data.method = path;
      data.url = path;
      data.uri = path;
      data.headers = args.metadata.getMap();
      if (data.headers && data.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        let bufferObj = Buffer.from(data.headers[NR_CSEC_FUZZ_REQUEST_ID], "base64");
        let decodedString = bufferObj.toString("utf8");
        data.headers[NR_CSEC_FUZZ_REQUEST_ID] = decodedString;
      }
      data.type = type;
      data.protocol = 'grpc';
      data.isGrpc = true;
      data.body = JSON.stringify(args.request);
      data.serverPort = shim.serverPort;
      const transactionId = transaction.id;
      requestManager.setRequest(transactionId, data);
    }
  } catch (error) {
    logger.error("Error occured while extracting grpc request", error);
  }
}

/**
 * Utilty to set grpc util Maps
 * @param {*} serviceObject 
 */
function serviceUtil(serviceObject) {
  let serviceValues = Object.values(serviceObject)[0];
  for (const [key, value] of Object.entries(serviceValues)) {
    let servObj = {
      'serviceName': serviceObject.serviceName,
      'originalName': value.originalName,
    }
    grpcutils.setMethod(value.path, servObj);
  }
}

function iterateNestedObjectForServiceLookup(result, serviceObject) {
  try {
    for (const key in result) {
      if (typeof result[key] === 'object' && result[key] !== 'null') {
        iterateNestedObjectForServiceLookup(result[key], serviceObject); // Recurse into nested object
      } else {
        let value = result[key];
        if (value && value.serviceName) {
          if (!value.type && value.serviceName) {
            grpcutils.setService(value.serviceName, serviceObject);
            serviceUtil(value);
          }
        }
      }
    }
  } catch (error) {
    logger.error("Error while getting service definition", error);
  }
}
