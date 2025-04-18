/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

 'use strict';

 const AsyncHooks = require('async_hooks');
 
 const NEW_LINE_IDENTIFIER = '\n';
 const NATIVE_LITERAL = 'native';
 const DOT_CHARACTER = '.';
 const MODULE_IDENTIFIER = '.Module';
 const ANONYMOUS_IDENTIFIER = '<anonymous>';
 
 const lineRegex = /at (?:(.+)\s+\()?(?:(.+?):(\d+)(?::(\d+))?|([^)]+))\)?/;
 const GET = 'get';
 const IS = 'is';
 
 exports.get = function (belowFn) {
     const oldLimit = Error.stackTraceLimit;
     Error.stackTraceLimit = 18;
     const dummyObject = {};
 
     const eid = AsyncHooks.executionAsyncId();
 
     const v8Handler = Error.prepareStackTrace;
     Error.prepareStackTrace = function (dummyObject, v8StackTrace) {
         return v8StackTrace;
     };
     Error.captureStackTrace(dummyObject, belowFn || exports.get);
 
     const v8StackTrace = dummyObject.stack;
     Error.prepareStackTrace = v8Handler;
     Error.stackTraceLimit = oldLimit;
 
     return v8StackTrace;
 };
 
 exports.parse = function (err) {
     if (!err.stack) {
         return [];
     }
 
     const self = this;
     const lines = err.stack.split(NEW_LINE_IDENTIFIER).slice(1);
 
     return lines
         .map(function (line) {
             if (line.match(/^\s*[-]{4,}$/)) {
                 return self._createParsedCallSite({
                     fileName: line,
                     lineNumber: null,
                     functionName: null,
                     typeName: null,
                     methodName: null,
                     columnNumber: null,
                     native: null
                 });
             }
 
             const lineMatch = line.match(lineRegex);
             if (!lineMatch) {
                 return;
             }
 
             let object = null;
             let method = null;
             let functionName = null;
             let typeName = null;
             let methodName = null;
             const isNative = (lineMatch[5] === NATIVE_LITERAL);
 
             if (lineMatch[1]) {
                 functionName = lineMatch[1];
                 let methodStart = functionName.lastIndexOf(DOT_CHARACTER);
                 if (functionName[methodStart - 1] === DOT_CHARACTER) { methodStart-- }
                 if (methodStart > 0) {
                     object = functionName.substr(0, methodStart);
                     method = functionName.substr(methodStart + 1);
                     const objectEnd = object.indexOf(MODULE_IDENTIFIER);
                     if (objectEnd > 0) {
                         functionName = functionName.substr(objectEnd + 1);
                         object = object.substr(0, objectEnd);
                     }
                 }
                 typeName = null;
             }
 
             if (method) {
                 typeName = object;
                 methodName = method;
             }
 
             if (method === ANONYMOUS_IDENTIFIER) {
                 methodName = null;
                 functionName = null;
             }
 
             const properties = {
                 fileName: lineMatch[2] || null,
                 lineNumber: parseInt(lineMatch[3], 10) || null,
                 functionName: functionName,
                 typeName: typeName,
                 methodName: methodName,
                 columnNumber: parseInt(lineMatch[4], 10) || null,
                 native: isNative
             };
 
             return self._createParsedCallSite(properties);
         })
         .filter(function (callSite) {
             return !!callSite;
         });
 };
 
 function CallSite (properties) {
     for (const property in properties) {
         this[property] = properties[property];
     }
 }
 
 const strProperties = [
     'this',
     'typeName',
     'functionName',
     'methodName',
     'fileName',
     'lineNumber',
     'columnNumber',
     'function',
     'evalOrigin'
 ];
 const boolProperties = [
     'topLevel',
     'eval',
     'native',
     'constructor'
 ];
 strProperties.forEach(function (property) {
     CallSite.prototype[property] = null;
     CallSite.prototype[GET + property[0].toUpperCase() + property.substr(1)] = function () {
         return this[property];
     };
 });
 boolProperties.forEach(function (property) {
     CallSite.prototype[property] = false;
     CallSite.prototype[IS + property[0].toUpperCase() + property.substr(1)] = function () {
         return this[property];
     };
 });
 
 exports._createParsedCallSite = function (properties) {
     return new CallSite(properties);
 };
 