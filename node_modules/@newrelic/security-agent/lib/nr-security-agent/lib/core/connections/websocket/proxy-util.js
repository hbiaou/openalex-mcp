/*
 * Copyright 2024 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict'

const { HttpsProxyAgent } = require('https-proxy-agent')
const logs = require('../../logging');
let logger = logs.getLogger();
const commonUtils = require('../../commonUtils');
const fs = require('fs');

let agentProxyWithKeepAlive = null

exports.proxyAgent = function proxyAgent(config) {
  if (null !== agentProxyWithKeepAlive) {
    return agentProxyWithKeepAlive
  }
  const proxyUrl = proxyOptions(config)
  let proxyOpts = {
    secureEndpoint: config.ssl,
    auth: proxyUrl.auth,
    ca: config?.certificates?.length ? config.certificates : [],
    keepAlive: true
  }
  let cert = '';
  try {
    const certPath = commonUtils.getPathOfCACert();
    cert = fs.readFileSync(certPath, 'utf8');
  } catch (error) {
    logger.error("Error in reading certificate:", error);

  }
  proxyOpts.ca.push(cert);
  logger.info(`Using proxy: ${proxyUrl}`)
  agentProxyWithKeepAlive = new HttpsProxyAgent(proxyUrl, proxyOpts)
  return agentProxyWithKeepAlive
}

/**
 * Utility to create proxy URL
 * @param config 
 * @returns 
 */
function proxyOptions(config) {
  let proxyUrl
  if (config.proxy) {
    proxyUrl = config.proxy
  } else {
    proxyUrl = 'https://'
    let proxyAuth = config.proxy_user
    if (config.proxy_pass !== '') {
      proxyAuth += ':' + config.proxy_pass
      proxyUrl += `${proxyAuth}@`
    }

    proxyUrl += `${config.proxy_host || 'localhost'}:${config.proxy_port || 80}`
  }
  return proxyUrl
}
