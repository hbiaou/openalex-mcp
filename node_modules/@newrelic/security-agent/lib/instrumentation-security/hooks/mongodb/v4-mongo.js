/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


'use strict'

const { instrumentCollection, instrumentCursor, instrumentDb } = require('./common')

module.exports = function instrument(shim, mongodb) {
  instrumentCursor(shim, mongodb.AbstractCursor)
  instrumentCursor(shim, mongodb.FindCursor)
  instrumentCursor(shim, mongodb.AggregationCursor)
  instrumentCollection(shim, mongodb.Collection)
  instrumentDb(shim, mongodb.Db)
}
