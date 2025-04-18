/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Pre-Release
 */


const grpcServiceMap = new Map();
const grpcMethodMap = new Map();
/**
 * Utility to set service based on key value pair
 * @param {*} key 
 * @param {*} value 
 */
function setService(key, value){
    grpcServiceMap.set(key,value);
}

/**
 * Utility to get service corresponding to key
 * @param {*} key 
 * @returns 
 */
function getService(key){
    return grpcServiceMap.get(key);
}

/**
 * Utility to set method object
 * @param {*} key 
 * @param {*} value 
 */
function setMethod(key, value){
    grpcMethodMap.set(key,value);
}

/**
 * Utility to get method object
 * @param {*} key 
 * @returns 
 */
function getMethod(key){
    return grpcMethodMap.get(key);
}

module.exports={
    setService,
    getService,
    grpcServiceMap,
    setMethod,
    getMethod,
    grpcMethodMap

}