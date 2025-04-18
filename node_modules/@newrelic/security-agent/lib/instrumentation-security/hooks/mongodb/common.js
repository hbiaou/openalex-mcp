/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

"use strict";

/* eslint sonarjs/cognitive-complexity: ["error", 18] -- TODO: https://issues.newrelic.com/browse/NEWRELIC-5252 */

const { CURSOR_OPS, COLLECTION_OPS, DB_OPS } = require("./constants");
const common = module.exports;
const requestManager = require("../../core/request-manager");
const async_hooks = require("async_hooks");
const secUtils = require("../../core/sec-utils");
const API = require("../../../nr-security-api");
const securityMetaData = require('../../core/security-metadata');
const { EVENT_TYPE, EVENT_CATEGORY } = require('../../core/event-constants');
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/constants');
const logger = API.getLogger();

function methodChecker(data) {
  data = data.toLowerCase();
  if (data.includes("delete")) {
    return "delete";
  } else if (data.includes("update") || data.includes("replace")) {
    return "update";
  } else if (data.includes("insert") || data.includes("write")) {
    return "insert";
  } else if (data.includes("find")) {
    return "find";
  } else {
    return "Unknown";
  }
}

function payloadType(obj) {
  if (obj) {
    if (obj.insert) {
      return "insert";
    } else if (obj.update) {
      return "update";
    } else if (obj.delete) {
      return "delete";
    } else if (obj.find) {
      return "find";
    } else {
      return "Unknown";
    }
  }
  else{
    return "Unknown";
  }

}

function queryHook(shim, mod, method) {
  shim.wrap(mod, method, function makeQueryWrapper(shim, fn) {
    logger.debug(`Instrumenting mongodb.${method}`);
    return function queryWrapper() {
      const request = requestManager.getRequest(shim);
      if (CURSOR_OPS.includes(method)) {
        if (!this.mongo_sec_hooked && this.operation && this.operation.cmd) {
          const pType = payloadType(this.operation.cmd);
          const payloadData = {
            payloadType: pType,
            payload: this.operation.cmd,
          };
          shim.interceptedArgs = payloadData;
        }
      } else {
        this.mongo_sec_hooked = true;

        const pType = methodChecker(method);
        const payloadData = {
          payloadType: pType,
          payload: arguments,
        };
        shim.interceptedArgs = payloadData;

      }

      try {
        if (request) {
          //generate event here
          const traceObject = secUtils.getTraceObject(shim);
          const secMetadata = securityMetaData.getSecurityMetaData(request, JSON.parse(JSON.stringify(shim.interceptedArgs)), traceObject, secUtils.getExecutionId(), EVENT_TYPE.NOSQL_DB_COMMAND, EVENT_CATEGORY.MONGO)
          const secEvent = API.generateSecEvent(secMetadata);
          API.sendEvent(secEvent);
          if (request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
            callbackHook(shim, arguments, arguments.length - 1, secEvent);
          }
        }
      } catch (error) {
      }
      

      return fn.apply(this, arguments);
    };
  });
}

/**
 * Instruments all methods from constants.CURSOR_OPS on a given
 * cursor class
 *
 * @param {Shim} shim
 * @param {Cursor} Cursor
 */
common.instrumentCursor = function instrumentCursor(shim, Cursor) {
  if (Cursor && Cursor.prototype) {
    const proto = Cursor.prototype;
    for (let i = 0; i < CURSOR_OPS.length; i++) {
      queryHook(shim, proto, CURSOR_OPS[i]);
    }
    queryHook(shim, proto, "each");
  }
};

/**
 * Instruments all methods from constants.COLLECTION_OPS on
 * the Collection class
 *
 * @param {Shim} shim
 * @param {Collection} Collection
 */
common.instrumentCollection = function instrumentCollection(shim, Collection) {
  if (Collection && Collection.prototype) {
    const proto = Collection.prototype;
    for (let i = 0; i < COLLECTION_OPS.length; i++) {
      queryHook(shim, proto, COLLECTION_OPS[i]);
    }
  }
};

/**
 * Instruments the execute method on
 * the BulkOperationBase class
 *
 * @param {Shim} shim
 * @param {BulkOperationModule} bulk operation module, typically from mongodb/lib/bulk/common
 * @param BulkOperationModule
 */
common.instrumentBulkOperation = function instrumentBulkOperation(
  shim,
  BulkOperationModule
) {
  const BulkOperationBase =
    BulkOperationModule && BulkOperationModule.BulkOperationBase;

  if (BulkOperationBase && BulkOperationBase.prototype) {
    const proto = BulkOperationBase.prototype;
    queryHook(shim, proto, "execute");
  }
};

/**
 * Instruments all methods from constants.DB_OPS on
 * the Db class.
 *
 * @param {object} params
 * @param {Shim} params.shim
 * @param {Db} params.Db
 * @param shim
 * @param Db
 */
common.instrumentDb = function instrumentDb(shim, Db) {
  if (Db && Db.prototype) {
    const proto = Db.prototype;
  }
  //here need to add hooks for DB ops
};

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

common.queryHookV2 = function queryHookV2(shim, mod, method) {
  shim.wrap(mod, method, function makeQueryWrapper(shim, fn) {
    logger.debug(`Instrumenting mongodb.${method}`);
    return function queryWrapper() {
      const request = requestManager.getRequest(shim);
      if (CURSOR_OPS.includes(method)) {
        if (!this.mongo_sec_hooked && this.cmd) {
          const pType = payloadType(this.cmd);
          const payloadData = {
            payloadType: pType,
            payload: this.cmd,
          };
          shim.interceptedArgs = payloadData;
        }
      } else {
        this.mongo_sec_hooked = true;

        const pType = methodChecker(method);
        const payloadData = {
          payloadType: pType,
          payload: arguments,
        };
        shim.interceptedArgs = payloadData;

      }

      if (request && shim.interceptedArgs) {
        //generate event here
        const traceObject = secUtils.getTraceObject(shim);
        const secMetadata = securityMetaData.getSecurityMetaData(request, JSON.parse(JSON.stringify(shim.interceptedArgs)), traceObject, secUtils.getExecutionId(), EVENT_TYPE.NOSQL_DB_COMMAND, EVENT_CATEGORY.MONGO)
        const secEvent = API.generateSecEvent(secMetadata);
        if (this.sec_executionId != secMetadata.executionId) {
          API.sendEvent(secEvent);
          this.sec_executionId = secMetadata.executionId;
        }

        if (request.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
          callbackHook(shim, arguments, arguments.length - 1, secEvent);
        }
      }
      return fn.apply(this, arguments);
    };
  });
}


