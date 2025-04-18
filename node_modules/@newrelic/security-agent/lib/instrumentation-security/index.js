/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const API = require('../nr-security-api');
const newrelic = API.newrelic;
const logger = API.getLogger();

logger.info("Started instrumentation using shimmer module");


newrelic.instrument({
  moduleName: 'child_process',
  isEsm: true,
  onRequire: require('./hooks/native/nr-childProcess'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})
newrelic.instrument({
  moduleName: 'http',
  isEsm: true,
  onRequire: require('./hooks/http/nr-http'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'https',
  isEsm: true,
  onRequire: require('./hooks/http/nr-http'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'fs',
  isEsm: true,
  onRequire: require('./hooks/fs/nr-fs'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: 'express',
  isEsm: true,
  onRequire: require('./hooks/express/nr-express'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentDatastore({
  moduleName: 'mysql',
  isEsm: true,
  onRequire: require('./hooks/mysql/nr-mysql'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentDatastore({
  moduleName: 'mysql2',
  isEsm: true,
  onRequire: require('./hooks/mysql/nr-mysql'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentDatastore({
  moduleName: 'mongodb',
  isEsm: true,
  onRequire: require('./hooks/mongodb/nr-mongodb'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'ldapjs',
  isEsm: true,
  onRequire: require('./hooks/ldap/nr-ldap'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'ldapts',
  isEsm: true,
  onRequire: require('./hooks/ldap/nr-ldap'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})


newrelic.instrument({
  moduleName: 'xpath',
  isEsm: true,
  onRequire: require('./hooks/xpath/nr-xpath'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})
newrelic.instrument({
  moduleName: 'xpath.js',
  isEsm: true,
  onRequire: require('./hooks/xpath/nr-xpath'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentDatastore({
  moduleName: 'pg',
  isEsm: true,
  onRequire: require('./hooks/postgres/nr-postgres'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: 'fastify',
  isEsm: true,
  onRequire: require('./hooks/fastify/nr-fastify'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})


newrelic.instrumentWebframework({
  moduleName: 'restify',
  isEsm: true,
  onRequire: require('./hooks/restify/nr-restify'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: '@koa/router',
  isEsm: true,
  onRequire: require('./hooks/koa/@koa/nr-@koa-router'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: 'koa-router',
  isEsm: true,
  onRequire: require('./hooks/koa/@koa/nr-@koa-router'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: '@hapi/hapi',
  isEsm: true,
  onRequire: require('./hooks/hapi/nr-hapi'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: 'director',
  isEsm: true,
  onRequire: require('./hooks/director/nr-director'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: '@nestjs/core',
  isEsm: true,
  onRequire: require('./hooks/@nestjs/nr-nestjs-core'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: 'undici',
  isEsm: true,
  onRequire: require('./hooks/undici/nr-undici'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: '@grpc/grpc-js/build/src/server',
  isEsm: true,
  onRequire: require('./hooks/grpc-js/nr-grpc').wrapServer,
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: '@grpc/grpc-js/build/src/make-client',
  isEsm: true,
  onRequire: require('./hooks/grpc-js/nr-grpc').wrapMakeClient,
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: '@grpc/grpc-js/build/src/resolving-call',
  isEsm: true,
  onRequire: require('./hooks/grpc-js/nr-grpc').wrapStartResolve,
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: '@grpc/grpc-js/build/src/call-stream',
  isEsm: true,
  onRequire: require('./hooks/grpc-js/nr-grpc').wrapStartCall,
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: '@grpc/grpc-js/build/src/call',
  isEsm: true,
  onRequire: require('./hooks/grpc-js/nr-grpc').wrapCall,
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'graphql/execution/execute',
  isEsm: true,
  onRequire: require('./hooks/graphql/nr-graphql'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'router',
  isEsm: true,
  onRequire: require('./hooks/express/nr-express').wrapRouter,
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'crypto',
  onRequire: require('./hooks/crypto/nr-crypto'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrumentWebframework({
  moduleName: 'next/dist/server/next-server',
  isEsm: true,
  onRequire: require('./hooks/nextjs/nr-next'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})

newrelic.instrument({
  moduleName: 'vm',
  isEsm: true,
  onRequire: require('./hooks/native/nr-vm'),
  onError: function intrumentErrorHandler(err) {
    logger.error(err.message, err.stack)
  }
})