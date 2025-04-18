module.exports = initialize;
const requestManager = require("../../core/request-manager");
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');
const logger = API.getLogger();

function initialize(shim, vm, moduleName) {
  logger.info('Instrumenting', moduleName);
  vmHooks(shim, vm, 'runInNewContext', moduleName);
  vmHooks(shim, vm, 'runInThisContext', moduleName);
  vmHooks(shim, vm, 'runInContext', moduleName);
}

/**
 * Wrapper to hook vm methods
 * @param {*} shim 
 * @param {*} vm 
 * @param {*} method 
 * @param {*} moduleName 
 */
function vmHooks(shim, vm, method, moduleName) {
  shim.wrap(vm, method, function makeWrapper(shim, fn) {
    logger.debug(`Instrumenting ${moduleName}.${method}`);
    return function wrapper() {
      const interceptedArgs = [arguments[0]];
      shim.interceptedArgs = interceptedArgs;
      const request = requestManager.getRequest(shim);
      if (request) {
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, interceptedArgs, traceObject, secUtils.getExecutionId(), "JAVASCRIPT_INJECTION", "JAVASCRIPT_INJECTION")
        const secEvent = API.generateSecEvent(secMetadata);
        this.secEvent = secEvent;
        API.sendEvent(secEvent);
      }

      const result = fn.apply(this, arguments);
      if (result && request && request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
        API.generateExitEvent(this.secEvent);
        delete this.secEvent
      }
      return result;
    };
  });
}