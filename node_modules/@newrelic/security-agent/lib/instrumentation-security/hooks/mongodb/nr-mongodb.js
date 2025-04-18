/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

"use strict";

const semver = require("semver");
const instrument = require("./v2-mongo")
const instrumentV3 = require("./v3-mongo");
const instrumentV4 = require("./v4-mongo");
const API = require("../../../nr-security-api");
const logger = API.getLogger();

// XXX: When this instrumentation is modularized, update this thread
// with a cautionary note:
// https://discuss.newrelic.com/t/feature-idea-using-mongoose-cursors-memory-leaking-very-quickly/49270/14
//
// This instrumentation is deep linked against in the mongoose instrumentation
// snippet.  The snippet will break once this file is moved from this
// location.

module.exports = initialize;

/**
 * Registers the query parser, and relevant instrumentation
 * based on version of mongodb
 *
 * @param {Agent} agent
 * @param {object} mongodb resolved package
 * @param {string} moduleName name of module
 * @param {Shim} shim
 */
function initialize(shim, mongodb, moduleName) {
  if(API && API.getNRAgent() && API.getNRAgent().config.security.exclude_from_iast_scan.iast_detection_category.nosql_injection){
    logger.warn('nosql_injection detection is disabled');
    return;
  }
  logger.info(`Instrumenting ${moduleName}`);
  if (!mongodb) {
    return;
  }

  const mongoVersion = shim.require("./package.json").version;
  logger.debug("mongoVersion:", mongoVersion);
  if (semver.satisfies(mongoVersion, ">=4.0.0")) {
    instrumentV4(shim, mongodb);
  } else if (semver.satisfies(mongoVersion, ">=3.0.6")) {
    instrumentV3(shim, mongodb);
  }else {
    instrument(shim, mongodb)
  }
}
