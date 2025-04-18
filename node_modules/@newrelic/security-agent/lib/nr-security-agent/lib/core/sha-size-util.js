/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const fs = require('fs');
const hash = require('hash.js');
const path = require('path');
const async_hooks = require('async_hooks');

const INCLUDED_FILE_EXT_REGEX = /(\.)(js|ts|ejs|html|properties|yml|yaml|json|hbs)$/;
const TWO_PIPES = '||';
const HEX_DIGEST = 'hex';
const thresh = 1024;
const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];

let logger;
let CurrentPromise = global.Promise;

module.exports = { getApplicationSHAAndSize, getApplicationSHAAndSizeSync, getSHA256ForFile, getSHA256ForFileSync, setPromise, setLogger, getSHA256ForData };

/**
 * This is a utility which is used to calculate
 * sha256 for the complete application context.
 */
async function getApplicationSHAAndSize (appPath) {
    if (CurrentPromise) {
        try {
            const shaMap = new Map();
            const shaAndSizeObj = await getSHA256AndSizeForPath(appPath, shaMap);
            return {
                sha256: getSHA256ForData(shaAndSizeObj.shaList.join(TWO_PIPES)),
                size: getHumanReadableSize(shaAndSizeObj.sizeList.reduce((result, value) => {
                    return result + value;
                }, 0)),
                shaMap: shaMap
            };
        } catch (err) {
            logger.error('Error while calculating SHA and size for application!');
            logger.debug(err);
            return {};
        }
    } else {
        logger.debug('Promise haven\'t been set!');
        return {};
    }
}

function getApplicationSHAAndSizeSync (appPath, skipRegex = null) {
    try {
        const shaMap = new Map();
        const shaAndSizeObj = getSHA256AndSizeForPathSync(appPath, shaMap, skipRegex);
        return {
            sha256: getSHA256ForData(shaAndSizeObj.shaList.join(TWO_PIPES)),
            size: getHumanReadableSize(shaAndSizeObj.sizeList.reduce((result, value) => {
                return result + value;
            }, 0)),
            shaMap: shaMap
        };
    } catch (err) {
        logger.error('Error while calculating SHA and size for application!');
        logger.debug(err);
        return {};
    }
}

/**
 * Gets sha256 and Size for all the elements of
 * given filePath.
 *
 * @param {String} filePath
 */
async function getSHA256AndSizeForPath (filePath, shaMap) {
    const pathStatObject = {};
    pathStatObject.shaList = [];
    pathStatObject.sizeList = [];
    try {
        const stats = await getStats(filePath);
        if (stats.isDirectory()) {
            const fileList = await getSortedDirContent(filePath);
            if (fileList) {
                for (const file of fileList) {
                    const calledStateObject = await getSHA256AndSizeForPath(file, shaMap);
                    pathStatObject.shaList = pathStatObject.shaList.concat(calledStateObject.shaList);
                    pathStatObject.sizeList = pathStatObject.sizeList.concat(calledStateObject.sizeList);
                }
            }
        } else if (filePath.match(INCLUDED_FILE_EXT_REGEX)) {
            const sha = await getSHA256ForFile(filePath);
            const fileSizeInBytes = stats.size;
            if (sha && sha !== null) {
                pathStatObject.shaList.push(sha);
                if (fileSizeInBytes) {
                    pathStatObject.sizeList.push(fileSizeInBytes);
                }
            }
        }
    } catch (err) {
        logger.error('Something bad happened while geting sha for ' + filePath);
        logger.debug(err);
    }
    return pathStatObject;
}

/**
 * Gets sha256 and Size for all the elements of
 * given filePath Synchronusly.
 *
 * @param {String} filePath
 */
function getSHA256AndSizeForPathSync (filePath, shaMap, skipRegex) {
    const pathStatObject = {
        shaList: [],
        sizeList: []
    };
    if (skipRegex && filePath && filePath.match(skipRegex)) {
        return pathStatObject;
    }
    try {
        const stats = getStatsSync(filePath);
        if (stats.isDirectory()) {
            const fileList = getSortedDirContentSync(filePath);
            if (fileList) {
                for (const file of fileList) {
                    const calledStateObject = getSHA256AndSizeForPathSync(file, shaMap, skipRegex);
                    pathStatObject.shaList = pathStatObject.shaList.concat(calledStateObject.shaList);
                    pathStatObject.sizeList = pathStatObject.sizeList.concat(calledStateObject.sizeList);
                }
            }
        } else if (filePath.match(INCLUDED_FILE_EXT_REGEX)) {
            const sha = getSHA256ForFileSync(filePath);
            const fileSizeInBytes = stats.size;
            if (sha && sha !== null) {
                pathStatObject.shaList.push(sha);
                if (fileSizeInBytes) {
                    pathStatObject.sizeList.push(fileSizeInBytes);
                }
            }
        }
    } catch (err) {
        logger.error('Something bad happened while geting sha for ' + filePath);
        logger.debug(err);
    }
    return pathStatObject;
}

/**
 * Gets all the source and prop files
 * in the passed directory.
 * @param {String} dirPath
 */
async function getSortedDirContent (dirPath) {
    return new CurrentPromise(async function (resolve, reject) {
        try {
            const stats = await getStats(dirPath);
            if (stats.isDirectory()) {
                fs.readdir(dirPath, function (err, files) {
                    if (err) {
                        logger.error('Unable to get directory content: ', dirPath);
                        reject(err);
                    }

                    // resolve file paths
                    for (let counter = 0; counter < files.length; counter++) {
                        files[counter] = path.resolve(dirPath, files[counter]);
                    }

                    // sort
                    files = files.sort();

                    resolve(files);
                });
            } else {
                const err = new Error('Not a directory: ' + dirPath);
                logger.error(err);
                reject(err);
            }
        } catch (err) {
            logger.error('Unable to get directory content: ', dirPath);
            reject(err);
        }
    });
}

/**
 * Gets all the source and prop files
 * in the passed directory Sync.
 * @param {String} dirPath
 */
function getSortedDirContentSync (dirPath) {
    try {
        const stats = getStatsSync(dirPath);
        if (stats.isDirectory()) {
            try {
                let files = fs.readdirSync(dirPath);

                // resolve file paths
                for (let counter = 0; counter < files.length; counter++) {
                    files[counter] = path.resolve(dirPath, files[counter]);
                }

                // sort
                files = files.sort();

                return files;
            } catch (err) {
                logger.error('Unable to get directory content: ', dirPath);
                throw err;
            }
        } else {
            const err = new Error('Not a directory: ' + dirPath);
            logger.error(err);
            throw err;
        }
    } catch (err) {
        logger.error('Unable to get directory content: ', dirPath);
        throw err;
    }
}

/**
 * Calculates SHA256 for a file.
 * @param {String} filePath
 */
async function getSHA256ForFile (filePath) {
    if (CurrentPromise) {
        return new CurrentPromise((resolve, reject) => {
            if (filePath) {
            } else {
                const err = new Error('Empty FilePath!');
                reject(err);
            }
        });
    } else {
        logger.debug('Promise haven\'t been set!');
        return {};
    }
}

/**
 * Calculates SHA256 for a file synchronously.
 * @param {String} filePath
 */
function getSHA256ForFileSync (filePath) {
    if (!filePath) {
        throw new Error('Empty FilePath!');
    }
    try {
        const fd = fs.openSync(filePath);
        const content = fs.readFileSync(fd, { encoding: 'UTF-8' });
        fs.closeSync(fd);
        return getSHA256ForData(content);
    } catch (err) {
        logger.error('Unable to calculate SHA256 for file: ' + filePath);
        throw err;
    }
}

/**
 * Generates SHA256 for passed data
 * @param {String} data
 */
function getSHA256ForData (data) {
    try {
        const calSha = hash.sha256().update(data).digest(HEX_DIGEST);
        return calSha;
    } catch (err) {
        logger.debug('Unable to calculate SHA256 for data.',err);
        return null;
    }
}

/**
 * returns HumanReadable form of passed Bytes
 * @param {Number} bytes
 */
function getHumanReadableSize (bytes) {
    if (Math.abs(bytes) < thresh) {
        return bytes + ' B';
    }
    let u = -1;
    do {
        bytes /= thresh;
        ++u;
    } while (Math.abs(bytes) >= thresh && u < units.length - 1);
    return bytes.toFixed(1) + ' ' + units[u];
}

/**
 * Sets logger for this module.
 */
function setLogger (logr) {
    logger = logr;
}

/**
 * Sets promise for this module.
 */
function setPromise (promise) {
    CurrentPromise = promise;
}

/**
 * Checks if the given path represents a directory
 */
async function getStats (path) {
    return new CurrentPromise((resolve, reject) => {
        fs.lstat(path, function (err, stat) {
            if (err) {
                logger.error('Unable to get stats for: ', path);
                reject(err);
            }
            resolve(stat);
        });
    });
}

/**
 * Checks if the given path represents a directory
 */
function getStatsSync (path) {
    return fs.lstatSync(path);
}
