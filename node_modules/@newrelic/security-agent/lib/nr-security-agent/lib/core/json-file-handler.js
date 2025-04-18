/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const fs = require('fs');
const path = require('path');

/**
 *  Entity which manages the json file.
 * 
 * @param {String} file 
 * @param {String} base Takes current directory if not specified.
 */
function JsonHandler(file, base = ".") {
    if (this.prototype.constructor !== JsonHandler) {
        return new JsonHandler(file, base);
    }
    this.fileName = base.concat(path.sep).concat(file);
    path.normalize(this.fileName);
    try {
        const readJSON = fs.readFileSync(this.fileName, { encoding: 'utf8' });
        this.json = JSON.parse(readJSON);
        
    } catch (err) {
        throw err
    }

}
JsonHandler.prototype = Object.create(JsonHandler);
JsonHandler.prototype.constructor = JsonHandler;

/**
     * get JSON Object
     */
JsonHandler.prototype.getJSON = function () {
    return this.json;
}


/**
* Update Source file synchronously
*/
JsonHandler.prototype.updateFileSync = function () {
    try {
        fs.writeFileSync(this.fileName, JSON.stringify(this.json, null, 2), { encoding: 'utf8' })
    } catch (err) {
        throw err
    }
}
/**
     * Update Source file asynchronously
     */
JsonHandler.prototype.updateFileAsync = function () {
    fs.writeFile(this.fileName, JSON.stringify(this.json, null, 2), { encoding: 'utf8' }, function (err) {
        if (err) {
            throw err
        }
    })

}


module.exports = {
    JsonHandler
}