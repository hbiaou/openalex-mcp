/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


"use strict";

const {
  instrumentBulkOperation,
  instrumentCollection,
  instrumentCursor,
  instrumentDb,
} = require("./common");

/**
 * Registers relevant instrumentation for mongo >= 3.0.6
 * In 3.0.6 they refactored their "APM" module which removed
 * a lot of niceities around instrumentation classes.
 * see: https://github.com/mongodb/node-mongodb-native/pull/1675/files
 * This reverts back to instrumenting pre-canned methods on classes
 * as well as sets up a listener for when commands start to properly
 * add necessary attributes to segments
 *
 * @param {Shim} shim
 * @param {object} mongodb resolved package
 */
module.exports = function instrument(shim, mongodb) {

  instrumentCursor(shim, mongodb.Cursor);
  instrumentCursor(shim, shim.require("./lib/aggregation_cursor"));
  instrumentCursor(shim, shim.require("./lib/command_cursor"));
  instrumentBulkOperation(shim, shim.require("./lib/bulk/common"));
  instrumentCollection(shim, mongodb.Collection);
  instrumentDb(shim, mongodb.Db);
};
