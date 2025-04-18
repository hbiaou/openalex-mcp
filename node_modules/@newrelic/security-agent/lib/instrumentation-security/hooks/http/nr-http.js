/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

module.exports = initialize
const requestManager = require('../../core/request-manager');
const { NR_CSEC_FUZZ_REQUEST_ID, QUESTION_MARK, EMPTY_STRING, UTF8, CONTENT_TYPE, TEXT_HTML, APPLICATION_JSON, APPLICATION_XML, APPLICATION_XHTML, TEXT_PLAIN, APPLICATION_X_FORM_URLENCODED, MULTIPART_FORM_DATA, COMMA, SEMI_COLON, EQUAL, SECURE, HTTPONLY, SAMESITE, STRICT, OBJECT } = require('../../core/constants');
const ARRAY_TYPE = 'Array';
const STRING_TYPE = 'string';
const BUFFER_TYPE = 'Buffer';
const UINT8ARRAY_TYPE = 'Uint8Array';
const OBJECT_TYPE = 'object'
const unescapeJs = require('unescape-js');
const ConType = require('content-type');
const lodash = require('lodash');
const URL = require('url')
const secUtils = require('../../core/sec-utils');
const API = require("../../../nr-security-api");
const logger = API.getLogger();
const NRAgent = API.getNRAgent();
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const hc = require('../../../nr-security-agent/lib/core/health-check');

const NRCSECTRACINGDATA = 'NR-CSEC-TRACING-DATA';
const SELFTEST = 'self-test';

const requestIp = require('request-ip');
const isInvalid = require('is-invalid-path');
const path = require('path');
const fs = require('fs');
const semver = require('semver');
const ExceptionReporting = require('../../../nr-security-agent/lib/core/ExceptionReporting');

const CSEC_SEP = ':IAST:';
const sep = require('path').sep;
const find = `${sep}{{NR_CSEC_VALIDATOR_HOME_TMP}}`;
const CSEC_HOME_TMP_CONST = new RegExp(find, 'g');
let CSEC_HOME = NRAgent && NRAgent.config.newrelic_home ? NRAgent.config.newrelic_home : NRAgent && NRAgent.config.logging.filepath ? path.dirname(NRAgent.config.logging.filepath) : require('path').join(process.cwd());
const CSEC_HOME_TMP = `${CSEC_HOME}/nr-security-home/tmp/language-agent/${process.env.applicationUUID}`
let lastTransactionId = EMPTY_STRING;
let uncaughtExceptionReportFlag = false;
const requestBodyLimit = 500;


/**
 * Entry point of http module hook
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName) {
  logger.info(`Instrumenting ${moduleName}`);
  emitHook(shim, mod, moduleName);
  createServerHook(shim, mod, moduleName);
  outboundHook(shim, mod, 'request', moduleName);
  if (semver.gte(process.version, '8.0.0')) {
    outboundHook(shim, mod, 'get', moduleName);
  }
  setupRequestMapCleanup()
}

/**
 * Adds a listener for when a transaction finishes
 * so the request manager map entry can be cleaned up
 */
function setupRequestMapCleanup() {
  if (NRAgent) {
    NRAgent.on('transactionFinished', function onTransactionFinished(transaction) {
      const requestData = requestManager.getRequestFromId(transaction.id);
      if (requestData && requestData.tempFiles && !lodash.isEmpty(requestData.tempFiles)) {
        const tempFiles = requestData.tempFiles;
        for (let i = 0; i < tempFiles.length; i++) {
          const file = tempFiles[i];
          deleteTempFileForIAST(file);
        }
      }
      // Here removing request data corresponding to transactionId
      setTimeout(() => {
        requestManager.gcRequestMap(transaction);
      }, 5000);
    })
  }
}


/**
 * Hook to intercept outbound http requests.
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function outboundHook(shim, mod, method, moduleName) {
  if (API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.ssrf) {
    logger.warn('ssrf detection is disabled');
    return;
  }
  logger.debug(`Instrumenting ${moduleName}.${method}`);
  shim.wrap(mod, method, function makeRequestWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function requestWrapper() {
      const request = requestManager.getRequest(shim);
      const data = {};
      data.headers = {};
      data.method = arguments[0].method;
      data.path = arguments[0].path;
      data.protocol = arguments[0].protocol ? arguments[0].protocol : 'http:';
      data.headers.host = arguments[0].hostname ? arguments[0].hostname : arguments[0].host;
      data.port = arguments[0].port;
      if (method === 'get') {
        data.method = 'GET';
        data.path = '/';
        data.headers.host = arguments[0];
        try {
          data.headers.host = data.headers.host.replace(/(^\w+:|^)\/\//, '');
        } catch (error) {

        }
      }
      let completeURL = data.protocol + '//' + data.headers.host + (data.port ? (':' + data.port) : '') + data.path;
      completeURL = completeURL.split(QUESTION_MARK)[0];

      if (request && !lodash.isEmpty(data.headers.host) && !lodash.isEmpty(data.path)) {
        const appUUID = API.getSecAgent().applicationInfo.applicationUUID;
        const id = secUtils.getExecutionId().toString();
        let generateFlag = false;
        if (arguments[0] && arguments[0].headers && arguments[0].headers.SECHOOK === id) {
          generateFlag = true;
        }
        if (!generateFlag) {
          const traceObject = secUtils.getTraceObject(shim);
          const secMetadata = securityMetaData.getSecurityMetaData(request, data, traceObject, secUtils.getExecutionId(), EVENT_TYPE.HTTP_REQUEST, EVENT_CATEGORY.HTTP)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);
          if (request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
            callbackHook(shim, arguments, arguments.length - 1, this.secEvent);
          }
        }

        let traceHeader = EMPTY_STRING;
        if (request.headers['nr-csec-tracing-data']) {
          traceHeader = request.headers['nr-csec-tracing-data'];
        }

        if (arguments[0] instanceof Object) {
          if (arguments[0] && arguments[0].headers && request.headers) {
            arguments[0].headers.SECHOOK = id;
            arguments[0].headers[NRCSECTRACINGDATA] = traceHeader + appUUID + '/' + this.secEvent.apiId + '/' + this.secEvent.id + ';';
          } else {
            arguments[0].headers = {};
            arguments[0].headers[NRCSECTRACINGDATA] = traceHeader + appUUID + '/' + this.secEvent.apiId + '/' + this.secEvent.id + ';';
            arguments[0].headers.SECHOOK = id;
          }
          if (request && request.headers[NR_CSEC_FUZZ_REQUEST_ID] && arguments[0].headers) {
            arguments[0].headers[NR_CSEC_FUZZ_REQUEST_ID] = request.headers[NR_CSEC_FUZZ_REQUEST_ID];
          }
        }
      }
      return fn.apply(this, arguments);
    };
  });
}

/**
 * Function to parse fuzzheaders and create temp files in case of dynamic scanning
 * Not functional
 * @param {*} fuzzheaders 
 */
function parseFuzzheaders(requestData, transactionId) {
  let fuzzheaders = requestData.headers;
  const policy = API.getPolicy();
  const dynamicScanningFlag = policy.data ? policy.data.vulnerabilityScan.iastScan.enabled : false;
  if (fuzzheaders[NR_CSEC_FUZZ_REQUEST_ID] && dynamicScanningFlag) {
    try {
      const additionalData = fuzzheaders[NR_CSEC_FUZZ_REQUEST_ID].split(CSEC_SEP);
      logger.debug('AdditionalData:', additionalData);
      if (additionalData.length >= 8) {
        let encryptedData = additionalData[6].trim();
        let hashVerifier = additionalData[7].trim();

        if (lodash.isEmpty(encryptedData) || lodash.isEmpty(hashVerifier)) {
          return;
        }
        let decryptedData = secUtils.decryptData(encryptedData);
        let verifiedHash = secUtils.hashVerifier(decryptedData, hashVerifier);
        logger.debug("verifiedHash:", verifiedHash);
        let filesToCreate = decryptedData.split(COMMA);
        if (verifiedHash) {
          logger.debug("Encrypted Data:", encryptedData);
          logger.debug("Decrypted Data:", decryptedData)
          logger.debug("fliesTocreate:", filesToCreate);
          for (let i = 0; i < filesToCreate.length; i++) {
            let file = filesToCreate[i].trim();
            file = decodeURIComponent(file);
            file = file.replace(CSEC_HOME_TMP_CONST, CSEC_HOME_TMP);
            file = path.resolve(file);
            const parentDir = path.dirname(file);
            if (!isInvalid(parentDir) && isPathInside(parentDir, CSEC_HOME_TMP)) {
              try {
                if (!fs.existsSync(parentDir)) {
                  secUtils.createPathIfNotExist(parentDir);
                } else {
                  logger.debug(parentDir + ' Already Exists');
                }
                fs.closeSync(fs.openSync(file, 'w'));

                requestData.tempFiles = [];
                requestData.tempFiles.push(file);
                requestManager.setRequest(transactionId, requestData);

              } catch (error) {
                logger.debug(error);
              }
            }
          }
        }
      }
    } catch (error) {
      logger.debug(error);
    }
  }
}

/**
 * Utility function to add request data in a Map
 * @param {*} shim 
 * @param {*} request 
 * @param {*} resp 
 */
function addRequestData(shim, request) {
  try {
    const data = Object.assign({});
    const transaction = shim.tracer.getTransaction(); 
    if (transaction) {
      data.protocol = (request.connection && request.connection.encrypted) ? 'https' : 'http';
      data.body = null;
      data.headers = request.headers;
      data.url = request.url;
      data.method = request.method;
      data.httpVersion = request.httpVersion;
      data.serverPort = transaction.port;
      data.contextPath = '/';
      const queryObject = URL.parse(request.url, true).query;
      data.parameterMap = {};
      if (queryObject) {
        Object.keys(queryObject).forEach(function (key) {
          if (queryObject[key]) {
            if (!data.parameterMap[key]) {
              data.parameterMap[key] = new Array(queryObject[key].toString());
            }
          }
        });
      }
      data.clientIP = requestIp.getClientIp(request);
      data.dataTruncated = false;
      const transactionId = transaction.id;
      const storedRequest = requestManager.getRequestFromId(transactionId);
      lastTransactionId = transactionId;
      if (storedRequest && storedRequest.uri) {
        data.uri = storedRequest.uri;
        data.parameterMap = storedRequest.parameterMap;
      }
      requestManager.setRequest(transactionId, data);
      if (shim.agent.getLinkingMetadata()) {
        let linkingMetadata = shim.agent.getLinkingMetadata();
        if (linkingMetadata['trace.id']) {
          let traceId = linkingMetadata['trace.id'];
          requestManager.setRequest(traceId, data)
        }
      }
      parseFuzzheaders(data, transactionId);
    }
  } catch (error) {
    logger.debug("Error while preparing incoming request:", error);
  }

}

/**
 * Wrappert to hook http.server.emit() 
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function emitHook(shim, mod, moduleName) {
  shim.wrap(mod && mod.Server && mod.Server.prototype, 'emit', function makeEmitWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.Server.prototype.emit`);
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function emitWrapper() {
      const req = arguments[1];
      const resp = arguments[2];

      if (arguments[0] == 'request') {
        if (NRAgent && !NRAgent.config.security.exclude_from_iast_scan.iast_detection_category.rxss && NRAgent.config.security.detection.rxss.enabled) {
          responseHook(resp, req, shim);
        }

        shim.wrap(req, 'on', function makeOnWrapper(shim, fn) {
          if (!shim.isFunction(fn)) {
            return fn
          }
          return function OnWrapper() {
            if (!requestManager.getRequest(shim)) {
              addRequestData(shim, req);
            }
            if (arguments[0] === 'end') {
              if (req && req.headers[SELFTEST] != 1) {
                hc.getInstance().registerHttpRequestCount();
              }
            }
            if (arguments[0] === 'data') {
              onDataHook(shim, arguments)
            }
            return fn.apply(this, arguments);
          }
        })
      }

      return fn.apply(this, arguments);
    }
  })
}

/**
 * Wrapper for http.createServer method
 * @param {*} shim 
 * @param {*} mod 
 */
function createServerHook(shim, mod, moduleName) {
  shim.wrap(mod, 'createServer', function createServerWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.createServer`);
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedCreateServer() {
      shim.wrap(arguments, '0', function appWrapper(shim, fn) {
        if (!shim.isFunction(fn)) {
          return fn
        }
        return function wrappedApp() {
          let req = arguments[0];
          if (!requestManager.getRequest(shim)) {
            addRequestData(shim, req);
          }
          return fn.apply(this, arguments);
        }
      })
      return fn.apply(this, arguments);
    }
  })
}

/**
 * Wrapper to hook http request body 
 * @param {*} shim 
 * @param {*} mod 
 */
function onDataHook(shim, mod) {
  shim.wrap(mod, '1', function makeOnDataWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function onDataWrapper() {
      const chunk = arguments[0];
      const chunkType = typeof chunk;
      const transaction = shim.tracer.getTransaction();
      if (chunkType === STRING_TYPE || chunkType === ARRAY_TYPE || chunkType === BUFFER_TYPE || chunkType === UINT8ARRAY_TYPE || chunkType === OBJECT_TYPE) {
        let data = chunk.toString();
        const transactionId = transaction.id;
        const requestData = requestManager.getRequestFromId(transactionId);
        if (requestData) {
          data = requestData.body ? requestData.body.concat(chunk.toString()) : chunk.toString();
          requestManager.updateRequestBody(shim, data, false);
          try {
            const contentLength = Buffer.byteLength(data, 'utf8');
            let bodyLimit = requestBodyLimit;
            if (!isNaN(bodyLimit)) {
              bodyLimit = bodyLimit * 1000;
              if (contentLength && contentLength > bodyLimit) {
                data = truncateStringToBytes(data, bodyLimit);
                requestManager.updateRequestBody(shim, data, true);
              }
            }

          } catch (error) {
            logger.error("Error while truncating request body", error);
          }
        }

      }
      return fn.apply(this, arguments);
    }
  })
}

/**
 * Wrapper to hook response.write() and reponse.end() method 
 * @param {*} resp 
 * @param {*} req 
 * @param {*} shim 
 */
function responseHook(resp, req, shim) {
  // wrapper for response.write() 
  resp.res = {};
  resp.res.body = EMPTY_STRING;

  shim.wrap(resp, 'write', function makeWriteWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedWrite() {
      const response = this;
      responseBodyCompute(response, arguments);
      return fn.apply(this, arguments);
    }
  })
  // wrapper for response.end() 
  shim.wrap(resp, 'end', function makeEndWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn
    }
    return function wrappedEnd() {
      const response = this;
      const request = requestManager.getRequest(shim);
      const txInfo = lodash.get(response, Object.getOwnPropertySymbols(response).find(symbol => symbol.toString() === 'Symbol(transactionInfo)'));
      try {
        if (txInfo && txInfo.error && request) {
          ExceptionReporting.generateExceptionReportingEvent(txInfo.error, request);
        }
        const responseCode = response.statusCode;
        if (responseCode && parseInt(responseCode / 100) == 5 && request) {
          if (txInfo && txInfo.error) {
            ExceptionReporting.generate5xxReportingEvent(txInfo.error, request, responseCode);
          }
          else {
            ExceptionReporting.generate5xxReportingEvent(null, request, responseCode);
          }
        }
      } catch (error) {
        logger.debug("Error while reporting error", error);
      }
      try {
        secureCookieCheck(response, shim);
        if (response && response.req && response.req.session) {
          trustBoundaryCheck(response.req.session, shim)
        }
      } catch (error) {
        logger.debug("Error while generating secure cookie event");
      }

      responseBodyCompute(response, arguments);

      const construct = API.checkForReflectedXSS(request, response.res.body, response.getHeaders());
      const policy = API.getPolicy();
      const dynamicScanningFlag = policy.data ? (policy.data.vulnerabilityScan?.enabled && policy.data.vulnerabilityScan.iastScan.enabled) : false;
      const type = response.getHeader(CONTENT_TYPE);
      let isUnsupportedType = isUnsupportedContentType(type, response);
      
      if (request && (construct || dynamicScanningFlag) && !isUnsupportedType) {
        const args = [];
        args.push(construct);
        args.push(response.res.body);
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, args, traceObject, secUtils.getExecutionId(), EVENT_TYPE.REFLECTED_XSS, EVENT_CATEGORY.REFLECTED_XSS)
        const secEvent = API.generateSecEvent(secMetadata);
        secEvent.httpResponse = {};
        secEvent.httpResponse.contentType = response.getHeader(CONTENT_TYPE);
        API.sendEvent(secEvent);
      }
      return fn.apply(this, arguments);
    }
  })
}
/**
 * Utility to check unsupported content types
 * @param {*} conType 
 * @returns 
 */
function isUnsupportedContentType(conType, response) {
  try {
    if(response.getHeaders()['etag']){
      return false;
    }
    if (!conType) {
      return true;
    }
    const unsupportedTypes = ["video/",
      "image/",
      "font/",
      "audio/",
      "application/zip",
      "application/epub+zip",
      "application/gzip",
      "application/java-archive",
      "application/msword",
      "application/octet-stream",
      "application/ogg",
      "application/pdf",
      "application/rtf",
      "application/vnd.amazon.ebook",
      "application/vnd.apple.installer+xml",
      "application/vnd.ms-excel",
      "application/vnd.ms-fontobject",
      "application/vnd.ms-powerpoint",
      "application/vnd.oasis.opendocument.presentation",
      "application/vnd.oasis.opendocument.spreadsheet",
      "application/vnd.oasis.opendocument.text",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.rar",
      "application/vnd.visio",
      "application/x-7z-compressed",
      "application/x-abiword",
      "application/x-bzip",
      "application/x-bzip2",
      "application/x-cdf",
      "application/x-freearc",
      "application/x-tar",
      "application/zip",
      "text/calendar"
    ];

    const startsWithAny = unsupportedTypes.some(prefix => conType.startsWith(prefix));
    return startsWithAny;
  } catch (error) {
    logger.debug("Error while checking unsupported content type");
  }

}

function responseBodyCompute(response, args) {
  let encoding = UTF8;
  const type = response.getHeader(CONTENT_TYPE);
  let isUnsupportedType = isUnsupportedContentType(type, response);
  if (isUnsupportedType) {
    return;
  }

  let contentType = TEXT_HTML;
  if (type) {
    const obj = ConType.parse(type);
    contentType = obj.type;
    encoding = obj.parameters.charset;
  }

  if (args[0]) {
    switch (contentType) {
      case APPLICATION_JSON:
        response.res.body += unescapeJs(args[0].toString(encoding));
        break;
      case APPLICATION_XML:
      case APPLICATION_XHTML:
      case TEXT_PLAIN:
      case TEXT_HTML:
      case APPLICATION_X_FORM_URLENCODED:
      case MULTIPART_FORM_DATA: {
        const data = args[0].toString(encoding);
        response.res.body += data;
        break;
      }
    }
  }
}

/**
 * Callback hook to generate exit event
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} fun 
 * @param {*} secEvent 
 */
function callbackHook(shim, mod, fun, secEvent) {
  shim.secEvent = secEvent;
  shim.wrap(mod, fun, function callbackWrapper(shim, fn) {
    if (!shim.isFunction(fn)) {
      return fn;
    }
    return function wrapper() {
      if (arguments && shim.secEvent) {
        API.generateExitEvent(shim.secEvent);
        delete shim.secEvent;
      }
      return fn.apply(this, arguments);
    }
  })
}

/**
 * Utility to check if child path is inside parent path
 * @param {*} childPath 
 * @param {*} parentPath 
 * @returns 
 */
function isPathInside(childPath, parentPath) {
  childPath = path.resolve(childPath);
  parentPath = path.resolve(parentPath);

  if (childPath === parentPath) {
    return false;
  }

  childPath += path.sep;
  parentPath += path.sep;

  return childPath.startsWith(parentPath);
}


/**
 * Delete Temporary file for IAST. Do not call this in RASP
 * @param {*} file 
 */
function deleteTempFileForIAST(file) {
  try {
    if (fs.existsSync(file)) {
      logger.debug("Deleting temporary file:", file);
      fs.unlinkSync(file);
    }
  } catch (error) {
    logger.debug("Unable to delete temporary file", error);
  }
}
/**
 * Collect and report the uncaught Exception
 */
process.on('uncaughtException', (err, origin) => {
  console.error(err);
  if (uncaughtExceptionReportFlag) {
    process.exit(1);
  }
  const request = requestManager.getRequestFromId(lastTransactionId);
  const exception = new ExceptionReporting.exceptionReporting(err, request);
  if (exception) {
    API.sendEvent(exception);
  }
  logger.error("An uncaughtException is detected:", err);
  uncaughtExceptionReportFlag = true;
});

/**
 * utility to parse response headers for cookie check
 * @param {*} headersString 
 * @returns 
 */
function responseRawHeaderParsing(headersString) {
  let setCookieValue;
  try {
    const headersArray = headersString.split('\r\n');
    for (const header of headersArray) {
      if (header.toLowerCase().startsWith('set-cookie:')) {
        setCookieValue = header.trim().replace('set-cookie:', '');
        break;
      }
    }
  } catch (error) {

  }
  return setCookieValue;
}

/**
 * Utility to check insecure cookie settings
 * @param {*} response 
 * @param {*} shim 
 */
function secureCookieCheck(response, shim) {
  let cookieHeader = response.getHeader('set-cookie') ? response.getHeader('set-cookie') : responseRawHeaderParsing(response._header);
  let cookieHeaderList = [];
  if (!cookieHeader) {
    return;
  }
  if (typeof cookieHeader === 'string') {
    cookieHeaderList.push(cookieHeader)
  }
  else {
    cookieHeaderList = cookieHeaderList.concat(cookieHeader);
  }
  let csec_request = requestManager.getRequest(shim);
  try {
    let parameters = [];
    for (const cookieString of cookieHeaderList) {
      if (cookieString) {
        const keyValuePairs = cookieString.split(SEMI_COLON);
        let params = {
          "isHttpOnly": false,
          "isSecure": false,
          "isSameSiteStrict": false,
        };
        for (let i = 0; i < keyValuePairs.length; i++) {
          const pair = keyValuePairs[i];
          const [key, value] = pair.trim().split(EQUAL);
          if (i == 0) {
            params.name = key;
            params.value = value;
          }

          if (key.toLowerCase() === SECURE) {
            params.isSecure = true;
          }
          else if (key.toLowerCase() === HTTPONLY) {
            params.isHttpOnly = true;
          }
          else if (key.toLowerCase() === SAMESITE && value.toLowerCase() === STRICT) {
            params.isSameSiteStrict = true;
          }
        }
        parameters.push(params);
      }
    }
    const traceObject = secUtils.getTraceObject(shim);
    const secMetadata = securityMetaData.getSecurityMetaData(csec_request, parameters, traceObject, secUtils.getExecutionId(), EVENT_TYPE.SECURE_COOKIE, EVENT_CATEGORY.SECURE_COOKIE)
    const secEvent = API.generateSecEvent(secMetadata);
    API.sendEvent(secEvent);
  } catch (error) {
    logger.debug("Error while generating secure cookie event:", error);
  }

}

function truncateStringToBytes(inputString, maxBytes) {
  if (!inputString || maxBytes <= 0) {
    return EMPTY_STRING; // Return an empty string if input is invalid
  }
  const buffer = Buffer.from(inputString, UTF8);
  if (buffer.length <= maxBytes) {
    return inputString;
  }
  const truncatedBuffer = buffer.slice(0, maxBytes);
  const truncatedString = truncatedBuffer.toString(UTF8);
  return truncatedString;
}

/**
 * Utility to generate trustboundary events.
 * @param {*} sessionObject 
 * @param {*} shim 
 */
function trustBoundaryCheck(sessionObject, shim) {
  try {
    const request = requestManager.getRequest(shim);
    let params = [];
    Object.keys(sessionObject).forEach(key => {
      if (sessionObject[key] && typeof sessionObject[key] != OBJECT) {
        params.push(String(key));
        params.push(String(sessionObject[key]));
      }
    });
    if (!lodash.isEmpty(params)) {
      const traceObject = secUtils.getTraceObject(shim);
      const secMetadata = securityMetaData.getSecurityMetaData(request, params, traceObject, secUtils.getExecutionId(), EVENT_TYPE.TRUSTBOUNDARY, EVENT_CATEGORY.TRUSTBOUNDARY)
      const secEvent = API.generateSecEvent(secMetadata);
      API.sendEvent(secEvent);
    }

  } catch (error) {
    logger.debug("Error while processing trustboundary", error);

  }

}

