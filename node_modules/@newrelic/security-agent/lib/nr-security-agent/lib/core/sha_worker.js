/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

const { workerData, parentPort } = require('worker_threads');
const shaSizeUtil = require('./sha-size-util');
const logs = require('./logging');
const logger = logs.getLogger(workerData.applicationUUID);
shaSizeUtil.setLogger(logger);
const MESSAGE = 'message';

async function computeSHA (path) {
    logger.info('Started computing SHA and size in worker thread');
    const data = await shaSizeUtil.getApplicationSHAAndSize(path, global.Promise);
    parentPort.postMessage(data);
    parentPort.unref();
    logger.debug('Terminating SHA worker');
    process.exit(0);
}

parentPort.on(MESSAGE, (param) => {
    computeSHA(param);
});
