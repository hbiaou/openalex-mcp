/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


const routeMap = new Map();
/**
 * Utility to set route based on key value pair
 * @param {*} key 
 * @param {*} value 
 */
function setRoute(key, value) {
    routeMap.set(key, value);
}

/**
 * Utility to get route corresponding to key
 * @param {*} key 
 * @returns 
 */
function getRoute(key) {
    return routeMap.get(key);
}

/**
 * Utility to get all api end points
 * @returns all keys from routeMap
 */
function getAllAPIEndPoints() {
    let apiEndpoints = [];
    try {
        routeMap.forEach((value, key) => {
            let obj = {};
            let splitted = key.split('@');
            obj.method = splitted[0];
            obj.path = splitted[1];
            obj.handler = routeMap.get(key);
            apiEndpoints.push(obj);
        })
    } catch (error) {

    }

    return apiEndpoints;
}

module.exports = {
    getRoute,
    setRoute,
    routeMap,
    getAllAPIEndPoints
}