/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


'use strict'

const DB_OPS = [
  'addUser',
  'authenticate',
  'collection',
  'collectionNames',
  'collections',
  'command',
  'createCollection',
  'createIndex',
  'cursorInfo',
  'dereference',
  'dropCollection',
  'dropDatabase',
  'dropIndex',
  'ensureIndex',
  'eval',
  'executeDbAdminCommand',
  'indexInformation',
  'logout',
  'open',
  'reIndex',
  'removeUser',
  'renameCollection',
  'stats',
  '_executeInsertCommand',
  '_executeQueryCommand'
]

const COLLECTION_OPS = [
  'aggregate',
  'bulkWrite',
  'count',
  'countDocuments',
  'createIndex',
  'deleteMany',
  'deleteOne',
  'distinct',
  'drop',
  'dropAllIndexes',
  'dropIndex',
  'ensureIndex',
  'find',
  'findAndModify',
  'findAndRemove',
  // 'findOne',
  'findOneAndDelete',
  'findOneAndReplace',
  'findOneAndUpdate',
  // 'findOneAndRemove',
  'geoHaystackSearch',
  'geoNear',
  'group',
  'indexes',
  'indexExists',
  'indexInformation',
  'insert',
  'insertMany',
  'insertOne',
  'isCapped',
  'mapReduce',
  'options',
  'parallelCollectionScan',
  'reIndex',
  'remove',
  'rename',
  'replaceOne',
  'save',
  'stats',
  'update',
  'updateMany',
  'updateOne'
]

const GRID_OPS = ['put', 'get', 'delete']

const CURSOR_OPS = ['nextObject', 'next', 'toArray', 'count', 'explain']

module.exports = {
  COLLECTION_OPS,
  CURSOR_OPS,
  DB_OPS,
  GRID_OPS
}
