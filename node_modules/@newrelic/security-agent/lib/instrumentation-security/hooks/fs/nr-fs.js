/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

module.exports = initialize;
const requestManager = require("../../core/request-manager");
const fs = require('fs');
const path = require('path');

const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const logger = API.getLogger();
const { STRING, QUESTIONMARK, DOTDOTSLASH, UNDEFINED, SELF_FD_PATH, SLASH, SLASHDOTDOT, NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');
const fsConsts = process.binding('constants').fs;
const agentModule = API.getSecAgent();
const lodash = require('lodash');

const requireHook = require('../require/nr-require');

const COPY_FILE = 'copyFile';
const RENAME = 'rename';
const FSReqCallback = 'FSReqCallback';
const FSReqWrap = 'FSReqWrap';
const OBJECT = 'object';
const semver = require('semver');

const functionsProbableToFA = [
  "fstat",
  "read",
  "readBuffers",
  "fdatasync",
  "fsync",
  "readdir",
  "readlink",
  "realpath",
];

let functionProbableToFI = [
  "rename",
  "ftruncate",
  "rmdir",
  "symlink",
  "link",
  "unlink",
  "fchmod",
  "chmod",
  "lchown",
  "fchown",
  "chown",
  "utimes",
  "futimes",
  "lutimes",
  "mkdtemp",
  "copyFile",
  "mkdir",
];

const promiseFunctionsProbableToFA = [
  "open",
  "readdir",
  "readlink",
  "readFile",
  "lstat",
  "stat",
];

const promiseFunctionProbableToFI = [
  "copyFile",
  "rename",
  "truncate",
  "rmdir",
  "mkdir",
  "symlink",
  "link",
  "unlink",
  "chmod",
  "lchmod",
  "lchown",
  "chown",
  "utimes",
  "lutimes",
  "mkdtemp",
  "writeFile",
  "appendFile",
];

/**
 * init function to apply hook on fs module.
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function initialize(shim, mod, moduleName) {
  if(API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.invalid_file_access){
    logger.warn('invalid_file_access detection is disabled');
    return;
  }
  logger.info(`Instrumenting ${moduleName}`);
  requireHook.initialize(shim)
  const binding = process.binding("fs");
  openHook(shim, binding, moduleName);
  probableToFAHooks(shim, mod, moduleName);
  probableToFIHooks(shim, mod, moduleName);
  const FSPromise = mod.promises;
  if (FSPromise) {
    probablePromiseToFAHooks(shim, FSPromise, moduleName);
    probablePromiseToFIHooks(shim, FSPromise, moduleName);
  }
}

/**
 * Wrapper for fs.open() function.
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function openHook(shim, mod, moduleName) {
  shim.wrap(mod, "open", function makeOpenWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.open`);
    return function openWrapper() {
      let parameters = Array.prototype.slice.apply(arguments);
      const interceptedArgs = [arguments[0]];
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if ((parameters[0] != undefined) && (typeof parameters[0] !== STRING) && (typeof parameters[0] !== UNDEFINED) && (parameters[0] !== UNDEFINED)) {
        try {
          parameters[0] = fs.readlinkSync(SELF_FD_PATH.concat(parameters[0]));
        } catch (err) {
          parameters[0] = arguments[0];
        }
      }
      if (request && typeof parameters[0] === STRING && !lodash.isEmpty(parameters[0])) {
        const policy = API.getPolicy();
        const dynamicScanningFlag = policy.data ? policy.data.vulnerabilityScan.iastScan.enabled : false;
        const url = request.url;
        const decodedURL = decodeURI(url);
        const trimedURL = url.split(QUESTIONMARK)[0];
        if (!trimedURL.includes(path.basename(parameters[0])) || decodedURL.includes(DOTDOTSLASH) || dynamicScanningFlag) {
          try {
            if (parameters[0].startsWith(DOTDOTSLASH)) {
              parameters[0] = API.getSecAgent().applicationInfo.serverInfo.deployedApplications[0].deployedPath + SLASH + parameters[0];
            } else if (parameters[0].startsWith(SLASHDOTDOT)) {
              parameters[0] = API.getSecAgent().applicationInfo.serverInfo.deployedApplications[0].deployedPath + parameters[0];
            } 
            
          } catch (error) {

          }
          let absoluteParameters = [parameters[0]];
          const traceObject = secUtils.getTraceObject(shim);
          const secMetadata = securityMetaData.getSecurityMetaData(request, absoluteParameters, traceObject, secUtils.getExecutionId(), getCaseType(parameters[1], parameters[0]), EVENT_CATEGORY.FILE)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);
          const callbackFlag = isCallback(arguments);
          if (callbackFlag && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
            callbackHook(shim, arguments[3], 'oncomplete', this.secEvent);
          }
        }

      }
      const result = fn.apply(this, arguments);
      if (result > 0 && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        //here generate exit event.
        API.generateExitEvent(this.secEvent);
        delete this.secEvent;
      }
      return result;
    };
  });
}

/**
 * Wrapper to hook all the function provided in list functionsProbableToFA
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function probableToFAHooks(shim, mod, moduleName) {
  functionsProbableToFA.forEach(function (fun) {
    shim.wrap(mod, fun, function makeFAWrapper(shim, fn) {
      logger.debug(`Instrumenting ${moduleName}.${fun}`);
      return function FAWrapper() {
        let parameters = Array.prototype.slice.apply(arguments);
        const interceptedArgs = [arguments[0]];
        shim.interceptedArgs = interceptedArgs;
        const request = requestManager.getRequest(shim);
        if (request && typeof arguments[0] === STRING && !lodash.isEmpty(arguments[0])) {
          const traceObject = secUtils.getTraceObject(shim);
          let absoluteParameters = [parameters[0]];
          const secMetadata = securityMetaData.getSecurityMetaData(request, absoluteParameters, traceObject, secUtils.getExecutionId(), EVENT_TYPE.FILE_OPERATION, EVENT_CATEGORY.FILE)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);
          const callbackFlag = isCallback(arguments);
          if (callbackFlag && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
            callbackHook(shim, arguments, arguments.length - 1, this.secEvent);
          }
        }
        return fn.apply(this, arguments);
      };
    });
  });
}

/**
 * Wrapper to hook all the function provided in list functionProbableToFI
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function probableToFIHooks(shim, mod, moduleName) {
  if (semver.satisfies(process.version, '>19.0.0')) {
    functionProbableToFI.push('writeFileSync');
  }
  functionProbableToFI.forEach(function (fun) {
    shim.wrap(mod, fun, function makeFIWrapper(shim, fn) {
      logger.debug(`Instrumenting ${moduleName}.${fun}`);
      return function FIWrapper() {
        let parameters = Array.prototype.slice.apply(arguments);
        const interceptedArgs = [arguments[0]];
        shim.interceptedArgs = interceptedArgs;
        const request = requestManager.getRequest(shim);
        if (request && typeof arguments[0] === STRING && !lodash.isEmpty(arguments[0])) {
          const traceObject = secUtils.getTraceObject(shim);
          let absoluteParameters = [parameters[0]];
          if (fun === COPY_FILE || fun === RENAME) {
            const secMetadata = securityMetaData.getSecurityMetaData(request, parameters[1], traceObject, secUtils.getExecutionId(), getCase(arguments[1]), EVENT_CATEGORY.FILE)
            this.secEvent = API.generateSecEvent(secMetadata);
            API.sendEvent(this.secEvent);
          }
          const secMetadata = securityMetaData.getSecurityMetaData(request, absoluteParameters, traceObject, secUtils.getExecutionId(), getCase(arguments[0]), EVENT_CATEGORY.FILE)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);
          const callbackFlag = isCallback(arguments);
          if (callbackFlag && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
            callbackHook(shim, arguments, arguments.length - 1, this.secEvent);
          }
        }
        return fn.apply(this, arguments);
      };
    });
  });
}

/**
 * Wrapper to hook all the function provided in list promiseFunctionsProbableToFA
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function probablePromiseToFAHooks(shim, mod, moduleName) {
  promiseFunctionsProbableToFA.forEach(function (fun) {
    logger.debug(`Instrumenting Promise ${moduleName}.${fun}`);
    shim.wrap(mod, fun, function makeFAWrapper(shim, fn) {
      return function FAWrapper() {
        let parameters = Array.prototype.slice.apply(arguments);
        const interceptedArgs = [arguments[0]];
        shim.interceptedArgs = interceptedArgs;
        const request = requestManager.getRequest(shim);
        if (request && typeof arguments[0] === STRING && !lodash.isEmpty(arguments[0])) {
          const traceObject = secUtils.getTraceObject(shim);
          let absoluteParameters = [parameters[0]];
          const secMetadata = securityMetaData.getSecurityMetaData(request, absoluteParameters, traceObject, secUtils.getExecutionId(), EVENT_TYPE.FILE_OPERATION, EVENT_CATEGORY.FILE)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);
        }
        return fn.apply(this, arguments);
      };
    });
  });
}

/**
 *  Wrapper to hook all the function provided in list promiseFunctionProbableToFI
 * @param {*} shim 
 * @param {*} mod 
 * @param {*} moduleName 
 */
function probablePromiseToFIHooks(shim, mod, moduleName) {
  promiseFunctionProbableToFI.forEach(function (fun) {
    logger.debug(`Instrumenting Promise ${moduleName}.${fun}`);
    shim.wrap(mod, fun, function makeFIWrapper(shim, fn) {
      return function FIWrapper() {
        let parameters = Array.prototype.slice.apply(arguments);
        const interceptedArgs = [arguments[0]];
        shim.interceptedArgs = interceptedArgs;
        const request = requestManager.getRequest(shim);
        if (request && typeof arguments[0] === STRING && !lodash.isEmpty(arguments[0])) {
          const traceObject = secUtils.getTraceObject(shim);
          let absoluteParameters = [parameters[0]];
          if (fun === COPY_FILE || fun === RENAME) {
            const secMetadata = securityMetaData.getSecurityMetaData(request, parameters[1], traceObject, secUtils.getExecutionId(), getCase(arguments[1]), EVENT_CATEGORY.FILE)
            this.secEvent = API.generateSecEvent(secMetadata);
            API.sendEvent(this.secEvent);
          }
          const secMetadata = securityMetaData.getSecurityMetaData(request, absoluteParameters, traceObject, secUtils.getExecutionId(), getCase(arguments[0]), EVENT_CATEGORY.FILE)
          this.secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(this.secEvent);
        }
        return fn.apply(this, arguments);
      };
    });
  });
}

/**
 * Utility to get case type based on flag and file path in case of file open operation 
 * @param {*} flag 
 * @param {*} filePath 
 * @returns 
 */
function getCaseType(flag, filePath) {
  if (flag) {
    switch (flag) {
      case fsConsts.O_RDONLY:
      case fsConsts.O_RDONLY | fsConsts.O_SYNC:
        return EVENT_TYPE.FILE_OPERATION;
      case fsConsts.O_RDWR:
      case fsConsts.O_RDWR | fsConsts.O_SYNC:
      case fsConsts.O_TRUNC | fsConsts.O_CREAT | fsConsts.O_WRONLY:
      case fsConsts.O_TRUNC | fsConsts.O_CREAT | fsConsts.O_WRONLY | fsConsts.O_EXCL:
      case fsConsts.O_TRUNC | fsConsts.O_CREAT | fsConsts.O_RDWR:
      case fsConsts.O_TRUNC | fsConsts.O_CREAT | fsConsts.O_RDWR | fsConsts.O_EXCL:
      case fsConsts.O_APPEND | fsConsts.O_CREAT | fsConsts.O_WRONLY:
      case fsConsts.O_APPEND | fsConsts.O_CREAT | fsConsts.O_WRONLY | fsConsts.O_EXCL:
      case fsConsts.O_APPEND | fsConsts.O_CREAT | fsConsts.O_WRONLY | fsConsts.O_SYNC:
      case fsConsts.O_APPEND | fsConsts.O_CREAT | fsConsts.O_RDWR:
      case fsConsts.O_APPEND | fsConsts.O_CREAT | fsConsts.O_RDWR | fsConsts.O_EXCL:
      case fsConsts.O_APPEND | fsConsts.O_CREAT | fsConsts.O_RDWR | fsConsts.O_SYNC:
        filePath = path.resolve(filePath);
        const appPath = API.getSecAgent().applicationInfo.serverInfo.deployedApplications[0].deployedPath;
        const isInPath = isPathInside(filePath, appPath);
        if (typeof filePath === STRING && isInPath) {
          return EVENT_TYPE.FILE_INTEGRITY;
        }
    }
  }
  return EVENT_TYPE.FILE_OPERATION;
}

/**
 * Utility to get case type based on provided file path
 * @param {*} filePath 
 * @returns 
 */
function getCase(filePath) {
  filePath = path.resolve(filePath);
  const appPath = API.getSecAgent().applicationInfo.serverInfo.deployedApplications[0].deployedPath;
  const isInPath = isPathInside(filePath, appPath);
  if (typeof filePath === STRING && isInPath) {
    return EVENT_TYPE.FILE_INTEGRITY;
  } else {
    return EVENT_TYPE.FILE_OPERATION;
  }
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
function isCallback(function_args) {
  try {
    const obj = function_args[function_args.length - 1];
    if (obj && typeof function_args[function_args.length - 1] === OBJECT && (obj.constructor.name === FSReqCallback || obj.constructor.name === FSReqWrap)) {
      return true;
    }
  } catch (error) {
    return false;
  }
  return false;
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
      if ((arguments[0] === null || arguments[0] === undefined) && shim.secEvent) {
        API.generateExitEvent(shim.secEvent);
        delete shim.secEvent;
      }
      return fn.apply(this, arguments);
    }
  })
}