/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


'use strict'

const { captureAttributesOnStarted, makeQueryDescFunc, queryHookV2 } = require('./common')

/**
 * Registers relevant instrumentation for mongo <= 3.0.6
 * and >= 2. This relies on the built-in "APM" hook points
 * to instrument their provided objects as well as sets
 * up a listener for when commands start to properly
 * add necessary attributes to segments
 *
 * @param {Shim} shim
 * @param {object} mongodb resolved package
 */
module.exports = function instrument(shim, mongodb) {

  const recordDesc = {
    Gridstore: {
      isQuery: false,
      makeDescFunc: function makeGridDesc(opName) {
        return { name: 'GridFS-' + opName, callback: shim.LAST }
      }
    },
    OrderedBulkOperation: { isQuery: true, makeDescFunc: makeQueryDescFunc },
    UnorderedBulkOperation: { isQuery: true, makeDescFunc: makeQueryDescFunc },
    CommandCursor: { isQuery: true, makeDescFunc: makeQueryDescFunc },
    AggregationCursor: { isQuery: true, makeDescFunc: makeQueryDescFunc },
    Cursor: { isQuery: true, makeDescFunc: makeQueryDescFunc },
    Collection: { isQuery: true, makeDescFunc: makeQueryDescFunc },
    Db: {
      isQuery: false,
      makeDescFunc: function makeDbDesc() {
        return { callback: shim.LAST }
      }
    }
  }

  // instrument using the apm api
  const instrumenter = mongodb.instrument(Object.create(null), instrumentModules)

  /**
   * Every module groups instrumentations by their
   * promise, callback, return permutations
   * Iterate over permutations and properly
   * wrap depending on the `recordDesc` above
   * See: https://github.com/mongodb/node-mongodb-native/blob/v3.0.5/lib/collection.js#L384
   *
   * @param _
   * @param modules
   */
  function instrumentModules(_, modules) {
    modules.forEach((module) => {
      const { obj, instrumentations, name } = module
      instrumentations.forEach((meta) => {
        applyInstrumentation(name, obj, meta)
      })
    })
  }

  /**
   * Iterate over methods on object and lookup in `recordDesc` to decide
   * if it needs to be wrapped as an operation or query
   *
   * @param {string} objectName name of class getting instrumented
   * @param {object} object reference to the class getting instrumented
   * @param {Define} meta describes the methods and if they are callbacks
   * promises, and return values
   */
  function applyInstrumentation(objectName, object, meta) {
    const { methods, options } = meta
    if (options.callback) {
      methods.forEach((method) => {
        const { isQuery, makeDescFunc } = recordDesc[objectName]
        const proto = object.prototype
        if (isQuery && method!='execute') {
          queryHookV2(shim, proto, method);
        } else if (isQuery === false) {
          // could be unset
          // shim.recordOperation(proto, method, makeDescFunc(shim, method))
        }
      })
    }

  }
}
