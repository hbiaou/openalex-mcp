/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Pre-Release
 */
const logger = require('../logging').getLogger();
const grpcutils = require('../../../../instrumentation-security/core/grpc-utils');
const clientMap = new Map();
let grpc;
const { NR_CSEC_FUZZ_REQUEST_ID } = require('../../core/sec-agent-constants');

/**
 * Utility to get client object
 * @param {*} config 
 * @returns 
 */
function getGPRCClient(config) {
    let grpc = require("@grpc/grpc-js");
    try {
        const serviceName = grpcutils.getMethod(config.method).serviceName;

        if (clientMap.has(serviceName)) {
            return clientMap.get(serviceName);
        }
        const serviceObject = grpcutils.getService(serviceName);
        const definition = grpc.loadPackageDefinition(serviceObject);
        let service = getNestedValue(definition, serviceName)
        if (service) {
            logger.info("GRPC client service extracted successfully");
        }
        const client = new service(
            "localhost:" + config.serverPort,
            grpc.credentials.createInsecure()
        );
        if (!clientMap.has(serviceName)) {
            clientMap.set(serviceName, client);
        }
        if(client){
            logger.info("GRPC IAST client created successfully");
        }
        return client;
    } catch (error) {
        logger.error("error while creating client:", error);
    }

}

/**
 * Utility to fire unary requests
 * @param {*} client 
 * @param {*} config 
 */
function fireUnaryRequest(client, config) {
    try {
        const methodObj = grpcutils.getMethod(config.requestURI);
        if (methodObj && methodObj.originalName) {
            let method = methodObj.originalName;
            let metadata = new grpc.Metadata();
            let bufferObj = Buffer.from(config.headers[NR_CSEC_FUZZ_REQUEST_ID], "utf8");
            let base64String = bufferObj.toString("base64");
            metadata.add(NR_CSEC_FUZZ_REQUEST_ID, base64String);
            client[method](JSON.parse(config.data), metadata, (err, res) => {
                if (err) {
                    logger.debug("Error occured:", err);
                    return
                }

                logger.info("Fuzz success: ", JSON.stringify(config));
                return res;
            })
        }
        else {
            logger.debug("Not Found:", config.url);
        }
    } catch (error) {
        logger.debug("Error while firing Unary request:", error);
    }
}

/**
 * fire gRPC request based on provided config 
 * @param {*} config 
 * @returns 
 */
function fireRequest(config) {
    try {
        grpc = require("@grpc/grpc-js");
    } catch (error) {
        logger.debug("Unable to import grpc module", error);
    }
    let client = getGPRCClient(config);
    fireUnaryRequest(client, config)
}


  function getNestedValue(obj, targetKey) {
    for (const key in obj) {
      if (key === targetKey) {
        return obj[key];
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        const result = getNestedValue(obj[key], targetKey);
        if (result !== undefined) {
          return result;
        }
      }
    }
    return undefined; // Key not found
  }


module.exports = {
    fireRequest
};
