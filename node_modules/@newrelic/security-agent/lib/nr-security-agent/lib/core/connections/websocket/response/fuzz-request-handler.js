/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

/* eslint-disable no-unused-vars */
const stringify = require('fast-safe-stringify');

const restClient = require('../../restclient');
const grpcClient = require('../../grpcClient');
const { Agent } = require('../../../agent');
const { FuzzFailEvent } = require('../../../FuzzFailEvent');
const { CSEC_HOME_TMP, COLON, NR_CSEC_FUZZ_REQUEST_ID, SLASH, CSEC_SEP, SEVERE } = require('../../../sec-agent-constants');
const LOCALHOST = 'localhost';
const COLON_SLASH_SLASH = '://';
const http = require('http');
const https = require('https');
const IASTUtil = require('./IASTUtils');
const LogMessage = require('../../../LogMessage');

require('dns').setDefaultResultOrder('ipv4first')
const PolicyManager = require('../../../Policy');


const find = `${SLASH}{{NR_CSEC_VALIDATOR_HOME_TMP}}`;
const CSEC_HOME_TMP_CONST = new RegExp(find, 'g');
const commonUtils = require('../../../commonUtils');

const CSEC_HOME_TMP_CONST_ENCODED = new RegExp('%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D', 'g');

let logger;
let lastFuzzEventTime = 0;
let iastIntervalConst;
let coolDownIntervalConst;
let additionalCoolDownTime = 0;
let fuzzedApiIDSet = new Set();
const API = require('../../../../../../nr-security-api');
const NRAgent = API.getNRAgent();


/**
 * utility to start IAST Schedular
 */
function startIASTSchedular() {
    if (Agent.getAgent().delayed) {
        let delayFromConfig = parseInt(NRAgent.config.security.scan_schedule.delay);
        let delay = delayFromConfig;
        if (isNaN(delay) || delay < 0) {
            delay = 0;
        }
        // logger.debug("IAST data pull request is scheduled at %s", require('../../../commonUtils').getScheduledScanTime(delay))
    }
    if (!Agent.getAgent().delayed) {
        Agent.getAgent().client.dispatcher(IASTUtil.generateIASTDataRequest());
    }

    if (iastIntervalConst) {
        clearInterval(iastIntervalConst);
    }
    let probingInterval = 5;

    const policyInstance = PolicyManager.getInstance();
    if (policyInstance.data) {
        probingInterval = policyInstance.data.vulnerabilityScan.iastScan.probing.interval;
    }
    if (isNaN(probingInterval)) {
        probingInterval = 5;
    }

    iastIntervalConst = setInterval(() => {
        if (Agent.getAgent().status.getStatus() == 'disabled' || Agent.getAgent().delayed) {
            return;
        }
        let data = IASTUtil.generateIASTDataRequest();
        let currentTime = Date.now();
        let completedListSize = IASTUtil.getCompletedRequestsMap().size;
        let pendingListSize = IASTUtil.getPendingRequestIds().length;
        let timeDiffInSeconds = ((currentTime - lastFuzzEventTime) / 1000);
        logger.trace("Time difference since last fuzz request:", timeDiffInSeconds);
        logger.trace("Completed requests so far:", completedListSize);
        logger.trace("Pending requests so far:", pendingListSize);

        if (timeDiffInSeconds > 5 && additionalCoolDownTime == 0) {
            Agent.getAgent().client.dispatcher(data);
        }
    }, probingInterval * 1000);
}

/**
 * Utility to log scanned apiId
 * @param {*} fuzzHeader 
 */
function logScannedApiId(fuzzHeader, requestURL) {
    try {
        let apiId = fuzzHeader.split(CSEC_SEP)[0]
        if (apiId && !fuzzedApiIDSet.has(apiId)) {
            fuzzedApiIDSet.add(apiId);
            logger.info("IAST Scan for API %s with ID : %s started.", requestURL, apiId);
        }
    } catch (error) {

    }

}

// handler function to parse fuzz event and prepare fuzz request
function handler(json) {
    if (Agent.getAgent().status.getStatus() == 'disabled') {
        return;
    }
    setLastFuzzEventTime();
    let rawFuzzRequest = json.arguments[0];

    try {
        rawFuzzRequest = rawFuzzRequest.replace(CSEC_HOME_TMP_CONST, CSEC_HOME_TMP);
        rawFuzzRequest = rawFuzzRequest.replace(CSEC_HOME_TMP_CONST_ENCODED, encodeURI(CSEC_HOME_TMP));
    } catch (error) {
        logger.debug("Error while replacing place holder", error);
    }

    let fuzzRequest;
    try {
        fuzzRequest = JSON.parse(rawFuzzRequest);
        fuzzRequest['id'] = json.id;
        IASTUtil.addPendingRequestId(json.id);
    } catch (error) {
        logger.error('Parsing exeception in fuzz request: ', error);

        const logMessage = new LogMessage.logMessage(SEVERE, 'Parsing exeception in fuzz request', __filename, error);
        require('../../../commonUtils').addLogEventtoBuffer(logMessage);
    }
    if (!fuzzRequest) {
        return;
    }
    logger.debug('Fuzz request received::' + JSON.stringify(json));
    logger.info('Fuzz request:: Method: ' + fuzzRequest.method);
    logger.info('Fuzz request:: Headers: ' + stringify(fuzzRequest.headers));
    logger.info('Fuzz request:: Data: ' + fuzzRequest.body);

    const fuzzDetails = { fuzzRequest, rawFuzzRequest };
    lastFuzzEventTime = Date.now();
    handleFuzzRequest(fuzzDetails);
};

/**
 * Handles the fuzz request logic after
 * initial parsing
 *
 * @param {Object} fuzzDetails
 */
function handleFuzzRequest(fuzzDetails) {
    const { fuzzRequest } = fuzzDetails;
    try {
        if (fuzzRequest.protocol == 'grpc') {
            const config = parseGRPCRequestToFuzz(fuzzRequest);
            config.headers['nr-csec-parent-id'] = fuzzRequest.id;
            IASTUtil.completedRequestsMapInit(fuzzRequest.id);
            grpcClient.fireRequest(config);
            if (fuzzRequest.headers && fuzzRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
                logScannedApiId(fuzzRequest.headers[NR_CSEC_FUZZ_REQUEST_ID], fuzzRequest.requestURI)
            }

            IASTUtil.removePendingRequestId(fuzzRequest.id);

        } else {
            const config = parseAxiosHttpRequestToFuzz(fuzzRequest);
            const type = config.headers['content-type'];
            if (type) {
                const splitted = type.split(';');
                if (splitted[0]) {
                    config.headers['content-type'] = splitted[0];
                }
            }

            config.headers['nr-csec-parent-id'] = fuzzRequest.id;

            IASTUtil.completedRequestsMapInit(fuzzRequest.id);

            if (fuzzRequest.headers && fuzzRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]) {
                logScannedApiId(fuzzRequest.headers[NR_CSEC_FUZZ_REQUEST_ID], fuzzRequest.requestURI)
            }


            logger.info('Firing http request:: URL: ' + config.url);
            const response = restClient.fireRequest(config);
            handleFuzzResponse(response, fuzzDetails);
        }
    } catch (err) {
        const fuzzFailEvent = new FuzzFailEvent(fuzzRequest.headers[NR_CSEC_FUZZ_REQUEST_ID]);
        logger.error(stringify(fuzzFailEvent));
        try {
            Agent.getAgent().client.dispatcher(fuzzFailEvent);
        } catch (error) {
            logger.debug('Error in sending fuzz request:', error.stack);
        }
    }
}

/**
 * Handles the fuzz response Promise.
 *
 * @param {Promise} response
 * @param {Object} fuzzDetails
 */
function handleFuzzResponse(response, fuzzDetails) {
    const { rawFuzzRequest, fuzzRequest } = fuzzDetails;
    if (response) {
        IASTUtil.removePendingRequestId(fuzzRequest.id);
        if (commonUtils.scanStartTime == 0) {
            commonUtils.scanStartTime = Date.now();
        }
        response.then(() => {
            logger.info('Fuzz success: ' + rawFuzzRequest);
        }).catch(() => {
            logger.debug('Error occured:', fuzzRequest.url, fuzzRequest);
        });
    }
}

/**
 * Parses the passed fuzz request object to
 * Axios config.
 *
 * @param {JSON} requestObject
 */
function parseAxiosHttpRequestToFuzz(requestObject) {
    let serverName = requestObject.serverName ? requestObject.serverName : LOCALHOST;
    let host = serverName + COLON + requestObject.serverPort;
    if (requestObject.headers && requestObject.headers['content-length']) {
        delete requestObject.headers['content-length'];
    }
    return {
        url: requestObject.protocol + COLON_SLASH_SLASH + host + requestObject.url,
        method: requestObject.method,
        data: requestObject.body,
        headers: requestObject.headers,
        timeout: 5000,
        httpAgent: new http.Agent({ keepAlive: true }),
        httpsAgent: new https.Agent({ keepAlive: true, rejectUnauthorized: false })
    };
}

/**
 * Parses the passed fuzz request object to
 * Axios config.
 *
 * @param {JSON} requestObject
 */
function parseGRPCRequestToFuzz(requestObject) {
    let serverName = requestObject.serverName ? requestObject.serverName : LOCALHOST;
    let host = serverName + COLON + requestObject.serverPort
    return {
        url: requestObject.protocol + COLON_SLASH_SLASH + host + requestObject.url,
        requestURI: requestObject.requestURI,
        protocol: requestObject.protocol,
        serverPort: requestObject.serverPort,
        method: requestObject.method,
        data: requestObject.body,
        headers: requestObject.headers,
        timeout: 5000,
    };
}


/**
 * set the handler logger
 * @param {*} l
 */
function setLogger(l) {
    logger = l;
};

/**
 * Sets the last fuzz event time epoch
 * @param {Number} time
 */
function setLastFuzzEventTime(time = Date.now()) {
    lastFuzzEventTime = time;
}


/**
 * Sets the last fuzz event time epoch
 * @param {Number} time
 */
function setAdditionalCoolDown(timeInSeconds) {
    additionalCoolDownTime = timeInSeconds ? timeInSeconds : 10;
    if (coolDownIntervalConst) {
        clearTimeout(coolDownIntervalConst)
    }
    coolDownIntervalConst = setTimeout(() => {
        additionalCoolDownTime = 0;
    }, timeInSeconds * 1000);
}

module.exports = {
    handler,
    setLogger,
    setLastFuzzEventTime,
    startIASTSchedular,
    setAdditionalCoolDown
};
