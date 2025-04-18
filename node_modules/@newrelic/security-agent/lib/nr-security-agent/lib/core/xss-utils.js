/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const _ = require('lodash');
const decode = require('unescape');
const querystring = require('querystring');

const { Agent } = require('./agent');

const htmlEntities = require('html-entities');
const { STRING } = require('./sec-agent-constants');

const tagNameRegex = /<([a-zA-Z_-]+[0-9]*|!--)/gmi;
const attribRegex = /([^(/\s<'">)]+?)(?:\s*)=\s*(('|")([\s\S]*?)(?:(?=(\\?))\5.)*?\3|.+?(?=\/>|>|\?>|\s|<\/|$))/gmi;
const ANGLE_END = '>';
const HTML_COMMENT_END = '-->';
const HTML_COMMENT_START = '!--';
const EQUALS = '=';
const SCRIPT_END = '</SCRIPT';
const ANGLE_END_CHAR = '>';
const FIVE_COLON = ':::::';
const EMPTY_STRING = '';
const ANGLE_START = '<';

/**
 * returns detected xss construct if any
 *
 * @param {ContextEntity} csecRequest
 * @param {Object} responseBody
 * @param {Object} responseHeaders
 * @returns
 */
function checkForReflectedXSS (csecRequest, responseBody, responseHeaders) {
    const combinedRequestData = decodeRequestData(csecRequest);
    const combinedResponseData = decodeResponseData(responseBody, responseHeaders);

    const combinedResponseDataString = [...combinedResponseData].join(FIVE_COLON);
    let attackConstructs = isXSS(combinedRequestData);

    // Agent.getAgent().logger.debug('attackConstructs:', attackConstructs);
    attackConstructs = Array.from(attackConstructs);
    for (let i = 0; i < attackConstructs.length; i++) {
        if (combinedResponseDataString.toLowerCase().includes(attackConstructs[i].toLowerCase())) {
            Agent.getAgent().logger.debug('construct found::', attackConstructs[i]);
            return attackConstructs[i];
        }
    }
    return EMPTY_STRING;
}

function decodeRequestData (csecRequest) {
    const processedData = new Set();
    if (csecRequest) {
        const body = csecRequest.body;
        const processedUrl = csecRequest.url;
        let processedBody = body;
        try {
            for (const [key, value] of Object.entries(csecRequest.headers)) {
                // For key
                processURLEncodedDataForXSS(processedData, key);

                // For Value
                processURLEncodedDataForXSS(processedData, value);
            }
            if (csecRequest.parameterMap) {
                for (const [key, value] of Object.entries(csecRequest.parameterMap)) {
                    if (key) {
                        processURLEncodedDataForXSS(processedData, key.toString());
                    }

                    if (value) {
                        processURLEncodedDataForXSS(processedData, value.toString());
                    }
                }
            }
            const querystringObj = querystring.decode(processedUrl);
            if (querystringObj) {
                for (const [key, value] of Object.entries(querystringObj)) {
                    if (key) {
                        processURLEncodedDataForXSS(processedData, key.toString());
                    }

                    if (value) {
                        processURLEncodedDataForXSS(processedData, value.toString());
                    }
                }
            }

            // For URL
            processURLEncodedDataForXSS(processedData, processedUrl);

            // For Body

            if (processedBody) {
                try {
                    const bodyObject = querystring.decode(processedBody);
                    if (bodyObject) {
                        for (const [k, v] of Object.entries(bodyObject)) {
                            processedData.add(v);
                            processedData.add(k);
                        }
                    }
                } catch (error) {

                }
                processedData.add(processedBody);

                const oldProcessedBody = processedBody;

                processedBody = safeDecode(processedBody);
                if (processedBody !== oldProcessedBody && processedBody.includes(ANGLE_START)) {
                    processedData.add(processedBody);
                }
            }
        } catch (err) {
            Agent.getAgent().logger.error('Exception occured while decoding request:', err);
        }
    }

    return processedData;
}

function decodeResponseData (responseBody, responseHeaders) {
    const processedData = new Set();
    const processedBody = responseBody || '';

    try {
        processedData.add(processedBody);
    } catch (err) {
        Agent.getAgent().logger.error('Exception occured while decoding response:', err);
    }

    return processedData;
}

function isXSS (combinedData) {
    const attackConstructs = new Set();
    try {
        for (const data of combinedData) {
            const constructs = getXSSConstructs(data);
            constructs.forEach(attackConstructs.add, attackConstructs);
        }
    } catch (error) {
        logger.debug("Error while getting rxss constucts:", error);
    }
    
    return attackConstructs;
}

function getXSSConstructs (data) {
    const constructs = new Set();
    let isAttackConstruct = false;
    let currPos = 0;
    let startPos = 0;
    let tmpCurrPos = 0;
    let tmpStartPos = 0;
    let matcher;
    let attribMatcher;
    while (currPos < data.length && typeof data == STRING ) {
        let tagName;

        matcher = tagNameRegex.exec(data);
        if (!matcher) {
            return constructs;
        }
        if ((matcher) !== null) {
            // This is necessary to avoid infinite loops with zero-width matches
            if (matcher.index === tagNameRegex.lastIndex) {
                tagNameRegex.lastIndex++;
            }

            tagName = matcher[1];

            tagNameRegex.lastIndex = currPos;
            if (!tagNameRegex.test(data)) {
                return constructs;
            }

            if (_.isEmpty(tagName)) {
                return constructs;
            }

            startPos = matcher.index;
            currPos = tagNameRegex.lastIndex - 1;

            if (HTML_COMMENT_START === tagName) {
                tmpCurrPos = data.indexOf(HTML_COMMENT_END, startPos);
                if (tmpCurrPos === -1) {
                    break;
                } else {
                    currPos = tmpCurrPos;
                    continue;
                }
            }
            tmpStartPos = tmpCurrPos = data.indexOf(ANGLE_END, startPos);
            if (tmpCurrPos === -1) {
                tmpStartPos = startPos;
            }
        }
        attribRegex.lastIndex = currPos;
        while ((attribMatcher = attribRegex.exec(data)) !== null) {
            // This is necessary to avoid infinite loops with zero-width matches
            if (attribMatcher.index === attribRegex.lastIndex) {
                attribRegex.lastIndex++;
            }

            let attribData = _.trim(attribMatcher[0]);

            currPos = attribRegex.lastIndex - 1;
            tmpCurrPos = data.indexOf(ANGLE_END, tmpStartPos);

            if ((tmpCurrPos === -1 || attribMatcher.index < tmpCurrPos)) {
                tmpStartPos = tmpCurrPos = attribRegex.lastIndex - 1;
                tmpStartPos++;
                if (_.isEmpty(attribMatcher[3]) && attribRegex.lastIndex >= tmpCurrPos) {
                    tmpStartPos = tmpCurrPos = data.indexOf(ANGLE_END, attribMatcher.index);
                    if (tmpStartPos > -1) {
                        attribData = attribData.substring(0, tmpStartPos);
                    }
                }
                const key = attribData.split(EQUALS)[0];
                const val = attribData.split(EQUALS)[1];
                const upperCaseAttribKey = key.toUpperCase();

                if (!_.isEmpty(key) && (upperCaseAttribKey.startsWith('ON') || upperCaseAttribKey === 'SRC' || upperCaseAttribKey === 'HREF' ||
                    upperCaseAttribKey === 'ACTION' || upperCaseAttribKey === 'FORMACTION' || upperCaseAttribKey === 'SRCDOC' ||
                    upperCaseAttribKey === 'DATA' || decode(val).toUpperCase().replace(/\s/g, '').includes('JAVASCRIPT:') ||
                    htmlEntities.decode(val).toUpperCase().replace(/\s/g, '').includes('JAVASCRIPT:'))) {
                    isAttackConstruct = true;
                }
            } else {
                break;
            }
        }

        if (tmpCurrPos > 0) {
            currPos = tmpCurrPos;
        }

        if (typeof data == STRING && data.charAt(currPos) !== ANGLE_END_CHAR) {
            const tmp = data.indexOf(ANGLE_END, currPos);
            if (tmp !== -1) {
                currPos = tmp;
            } else if (!isAttackConstruct) {
                continue;
            }
        }
        if (tagName && tagName.toUpperCase().trim() === 'SCRIPT') {
            const locationOfEndTag = data.toUpperCase().indexOf(SCRIPT_END, currPos);
            if (locationOfEndTag !== -1) {
                const body = data.substring(currPos + 1, locationOfEndTag);
                if (body) {
                    constructs.add(data.substring(startPos, currPos + 1) + body);
                    continue;
                }
            } else {
                let body = data.substring(currPos + 1);
                const tagEnd = body.indexOf(ANGLE_END);

                if (!_.isEmpty(body) && tagEnd !== -1) {
                    body = data.substring(tagEnd);
                    constructs.add(data.substring(startPos, currPos + 1) + body);
                    break;
                }
            }
        }

        if (isAttackConstruct) {
            constructs.add(data.substring(startPos, currPos + 1));
        }
    }

    return constructs;
}

function processURLEncodedDataForXSS (processedData, data) {
    let key = data;
    let oldKey = String(key);
    do {
        if (key.includes(ANGLE_START)) {
            processedData.add(key);
        }
        oldKey = key;
        key = safeDecode(key);
    } while (oldKey !== key);
}

function safeDecode (data) {
    let decodedData = EMPTY_STRING;
    try {
        decodedData = decodeURIComponent(data);
    } catch (err) {
        decodedData = data;
    }
    return decodedData;
}

module.exports = {
    checkForReflectedXSS
};
