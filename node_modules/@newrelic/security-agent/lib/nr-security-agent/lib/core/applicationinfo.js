/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */

'use strict';

const { BasicInfo } = require('./event');
const { JsonHandler } = require('./json-file-handler');
const fs = require('fs');
const shaSizeUtil = require('./sha-size-util');
const _ = require('lodash');
const OS = require('os');
const { Agent } = require('./agent');
const commonUtils = require('./commonUtils');

const events = require('events');
const eventEmitter = new events.EventEmitter();

const LOG_MESSAGES = require('./sec-agent-constants').LOG_MESSAGES;
const {
    IS_LAMBDA_ENV,
    AWS_LAMBDA_QUALIFIED_ARN_ENV_IDENTIFIER,
    AWS_LAMBDA_FUNCTION_NAME_ENV_IDENTIFIER,
    AWS_LAMBDA_FUNCTION_VERSION_ENV_IDENTIFIER,
    AWS_SESSION_TOKEN_ENV_IDENTIFIER,
    EMPTY_APPLICATION_UUID,
    SLASH
} = require('./sec-agent-constants');
const API = require('../../../nr-security-api');
const NRAgent = API.getNRAgent();

const SELF_PROC_DIR = '/proc/self';
const CGROUP_FILE_NAME = '/proc/self/cgroup';
const STAT = '/stat';
const CMD_LINE_FILE = '/cmdline';
const DIR_IDENTIFIER = SLASH;
const NEW_LINE_SEPERATOR = '\n';
const CGROUP_FILE = '/cgroup';
const ESCAPED_DOT = '.';
const FINALIZED_KEYWORD = 'finalized';
const APPLICATION_INFO_KEYWORD = 'applicationinfo';
const MODULE_INTERNAL = 'module';
const STATIC_ATTACHMENT_TYPE = 'STATIC';
const SERVER_INFO_NAME = 'Node.js';
const DOCKER_IDENTIFIER = 'docker/';
const DOCKER_IDENTIFIER_1_13 = '/docker-';
const KUBPODS_IDENTIFIER = 'kubepods/';
const ECS_DIR = 'ecs/';
const LXC_IDENTIFIER = 'lxc/';
const SCOPE_IDENTIFIER = '.scope';
const SPACE_CHARACTER = ' ';
const PACKAGE_JSON_FILE = 'package.json';
const EMPTY_STRING = '';
const LIBPOD = '/libpod-';
const DOCKER_CONTAINER = '/docker/containers/';
const PROC_SELF_MOUNTINFO = '/proc/self/mountinfo';

let applicationInfo;
let isFinalized = false;

const SPACE_SEPERATOR_REGEX = /\s+/g;
const logs = require('./logging');
const logger = logs.getLogger();
const initLogger = logs.getInitLogger();

function localIpAddress () {
    try {
        const interfaces = Object.values(OS.networkInterfaces());
        for (const iface of interfaces) {
            for (const alias of iface) {
                if ((alias.family === "IPv4" || alias.family === 4) && alias.address !== "127.0.0.1" && !alias.internal) {
                    return alias.address;
                }
            }
        }
    } catch (error) {

    }
    return "0.0.0.0";
}

/**
 * Constructs the applicationinfo object
 */
function ApplicationInfo () {
    BasicInfo.apply(this);

    const containerId = getContainerID();
    const k8sHost = isK8S();
    const ECSEnv = isECSEnv();
    const isLambda = IS_LAMBDA_ENV;
    this.jsonName = APPLICATION_INFO_KEYWORD;
    if (NRAgent && NRAgent.config) {
        this.appEntityGuid = NRAgent.config.entity_guid;
        this.appAccountId = NRAgent.config.account_id;
    }
    this.eventType = 'sec_appinfo';
    this.startTime = Date.now();
    this.binaryPath = process.execPath;
    this.binaryName = process.title;
    this.binaryVersion = process.versions.node;
    this.libraryPath = require(MODULE_INTERNAL).globalPaths;
    this.applicationUUID = commonUtils.getUUID();
    this.osArch = process.arch;
    this.osName = process.platform;
    this.pid = process.pid;
    this.userDir = process.env.PWD;
    this.user = process.env.USER;
    this.agentAttachmentType = STATIC_ATTACHMENT_TYPE;
    this.identifier = {};

    this.identifier = buildIdentifier(this.identifier);
    this.identifier.envInfo = {};
    this.identifier.envInfo.name = getHostName();
    this.identifier.envInfo.ipaddress = localIpAddress();

    if (!_.isEmpty(containerId)) {
        this.identifier.id = containerId;
        this.identifier.kind = "CONTAINER";
        const containerProps = setContainerProperties(this.identifier);
        this.identifier.envInfo = containerProps;
        if (k8sHost) {
            this.identifier.kind = "POD";
            this.identifier.envInfo = setPodProperties(this.identifier, containerProps);
        }
        if (ECSEnv) {
            this.identifier.kind = "ECS";
            this.identifier.envInfo = setECSProperties(this.identifier);
        }
    } else if (isLambda) {
        const lambdaARN = process.env[AWS_LAMBDA_QUALIFIED_ARN_ENV_IDENTIFIER];
        const lambdaVersion = process.env[AWS_LAMBDA_FUNCTION_VERSION_ENV_IDENTIFIER];
        this.applicationUUID = _.isEmpty(lambdaARN) ? ApplicationInfo.Constants.EMPTY_UUID : `${lambdaARN}:${lambdaVersion}`;
        this.identifier.isHost = true;
        this.identifier.isLambda = isLambda;
        this.identifier.lambdaFunctionARN = _.isEmpty(lambdaARN)
            ? `${process.env[AWS_LAMBDA_FUNCTION_NAME_ENV_IDENTIFIER]}:${lambdaVersion}`
            : `${lambdaARN}:${lambdaVersion}`;
        this.identifier.lambdaAWSSessionToken = process.env[AWS_SESSION_TOKEN_ENV_IDENTIFIER];
        
    } else {
        this.identifier.kind = "HOST";
        this.identifier.envInfo = setHostProperties();
    }


    this.serverInfo = {};
    this.serverInfo.name = SERVER_INFO_NAME;
    this.runCommand = getRunCommand();
    this.cmdline = process.argv;
    const procStartTime = getProcStartTime(this.pid);
    this.procStartTime = procStartTime || null;
}
ApplicationInfo.prototype = Object.create(BasicInfo.prototype);
ApplicationInfo.prototype.constructor = ApplicationInfo;

ApplicationInfo.prototype.getLambdaFunctioninfo = function getLambdaFunctioninfo () {
    return {
        isLambda: this.identifier.isLambda,
        lambdaFunctionARN: this.identifier.lambdaFunctionARN,
        lambdaAWSSessionToken: this.identifier.lambdaAWSSessionToken
    };
};

ApplicationInfo.prototype.setUUID = function setUUID (uuid) {
    this.applicationUUID = uuid;
    Agent.getAgent().setApplicationInfo(this);
    Agent.eventEmitter.emit(Agent.EVENTS.RECONNECT_WS_EVENT);
};

ApplicationInfo.prototype.getIdentifier = function getIdentifier () {
    return this.identifier;
};

ApplicationInfo.prototype.setIdentifier = function setIdentifier (identifierJSON) {
    this.identifier = identifierJSON;
};

ApplicationInfo.prototype.updateSHAAndSize = async function updateSHAAndSize (GlobalPromise) {
    const applicationInfo = this;
    const deployedApplications = applicationInfo && applicationInfo.serverInfo && applicationInfo.serverInfo.deployedApplications;

    // set Promise object for module
    shaSizeUtil.setPromise(GlobalPromise);

    // if there are no applications detected
    if (!deployedApplications) return;

    // calculate and add sha and size info
    const [application] = deployedApplications;

    // For lambda we would want to skip the
    // sha calculation on application files
    if (IS_LAMBDA_ENV) {
        return;
    }

    // add sha256 of binary.
    applicationInfo.sha256 = await shaSizeUtil.getSHA256ForFile(process.argv[0]);

    let stat = {};
    if (commonUtils.hasWorker()) {
        stat = await getApplicationSHAAndSizeFromWorker(applicationInfo, application.deployedPath);
    } else {
        stat = await shaSizeUtil.getApplicationSHAAndSize(application.deployedPath, GlobalPromise);
    }
    application.sha256 = stat.sha256;
    application.size = stat.size;
    application.contextPath = '/';
    application.isEmbedded = true;
    process.serverPort = process.serverPort || process.env.PORT ;
    application.ports = [process.serverPort || 0];
    // emit finalization of application info
    if (Agent.getAgent()) {
        Agent.getAgent().setApplicationInfo(applicationInfo);
    }
};

ApplicationInfo.Constants = {
    EMPTY_UUID: EMPTY_APPLICATION_UUID
};

/**
 * Adds the given property and its value to
 * the applicationinfo object.
 *
 * @param {string} property
 * @param {*} value
 * @throws error if property value exists.
 * @throws error if applicationinfo is finalized.
 *
 * @returns {boolean} success
 */
function addProperty (property, value) {
    if (!isFinalized && applicationInfo) {
        let currentObject = applicationInfo;
        const properties = property.split(ESCAPED_DOT);
        for (let index = 0; index < properties.length - 1; index++) {
            if (currentObject[properties[index]]) {
                if (typeof currentObject[properties[index]] === 'object') {
                    currentObject = currentObject[properties[index]];
                } else {
                    throw new Error('CSEC-Agent: Unable to add the given property to ApplicationInfo, property value already exists!');
                }
            } else {
                currentObject[properties[index]] = {};
                currentObject = currentObject[properties[index]];
            }
        }
        currentObject[properties[properties.length - 1]] = value;
        return true;
    } else {
        throw new Error('CSEC-Agent: Cannot update property when ApplicationInfo is finalized or empty!');
    }
}

/**
 * Returns the current instanceof applicationinfo,
 * creates one if not already created.
 *
 * @returns {ApplicationInfo} instance
 */
function getInstance () {
    if (!applicationInfo) {
        applicationInfo = new ApplicationInfo();
    }
    return applicationInfo;
}

/**
 * Marks the applicationinfo as finalized.
 */
function finalize () {
    if (!isFinalized) {
        isFinalized = true;
        eventEmitter.emit(FINALIZED_KEYWORD);
    }
}

/**
 * Checks if the current application info is finalized.
 *
 * @returns {boolean} isFinalized
 */
function finalized () {
    return isFinalized;
}

/**
 * Retrives the container ID in which the current process
 * is running.
 *
 * @returns {string} ContainerID if found, false otherwise.
 */
function getContainerID () {
    let lines, index;

    // code to get containerId from /proc/self/mountinfo file
    try {
        const mountinfoFile = fs.readFileSync(PROC_SELF_MOUNTINFO);
        lines = mountinfoFile.toString().split(NEW_LINE_SEPERATOR);
        for (const st of lines) {
            index = st.indexOf(DOCKER_CONTAINER);
            if (index > -1) {
                const splitted = st.split(DOCKER_CONTAINER);
                return splitted[splitted.length - 1].split(SLASH)[0];
            }
        }
    } catch (error) {
    }

    // code to get containerId from /proc/self/cgroup file
    try {
        const cgroupFile = fs.readFileSync(SELF_PROC_DIR + CGROUP_FILE);
        lines = cgroupFile.toString().split(NEW_LINE_SEPERATOR);
    } catch (err) {
        return false;
    }
    for (const st of lines) {
        index = st.lastIndexOf(DOCKER_IDENTIFIER);
        if (index > -1) {
            return st.substring(index + 7);
        }

        index = st.lastIndexOf(ECS_DIR);
        if (index > -1) {
            return st.substring(st.lastIndexOf(DIR_IDENTIFIER) + 1);
        }

        index = st.indexOf(KUBPODS_IDENTIFIER);
        if (index > -1) {
            return st.substring(st.lastIndexOf(DIR_IDENTIFIER) + 1);
        }
        // To support docker older versions
        index = st.lastIndexOf(LXC_IDENTIFIER);
        if (index > -1) {
            return st.substring(index + 4);
        }
        // docker version 1.13.1
        index = st.lastIndexOf(DOCKER_IDENTIFIER_1_13);
        const indexEnd = st.lastIndexOf(SCOPE_IDENTIFIER);
        if (index > -1 && indexEnd > -1) {
            return st.substring(index + 8, indexEnd);
        }

        // podman
        if (st.indexOf(LIBPOD) > -1 && st.indexOf(SCOPE_IDENTIFIER) > -1) {
            const containerId = st.split(LIBPOD).pop().split(SCOPE_IDENTIFIER)[0];
            if (!_.isEmpty(containerId)) {
                return containerId;
            }
        }
    }

    return false;
}
/**
 * Extracts cmdline from proc.
 *
 */
function getCmdLine () {
    try {
        const cmdlineFile = fs.readFileSync(SELF_PROC_DIR + CMD_LINE_FILE);
        if (!cmdlineFile) {
            return EMPTY_STRING;
        }
        const lines = cmdlineFile.toString().split(NEW_LINE_SEPERATOR);
        const cmdline = lines[0];
        if (cmdline) {
            return cmdline;
        }
    } catch (err) {
        return EMPTY_STRING;
    }
}

/**
 * Extracts runCommand from process var.
 *
 */
function getRunCommand () {
    const argvs = Array.prototype.slice.call(process.argv, 0, process.argv.length);
    const execArgv = Array.prototype.slice.call(process.execArgv, 0, process.execArgv.length);
    const runCommand = [];
    runCommand.push(argvs.shift());
    let element = null;
    while ((element = execArgv.shift())) {
        runCommand.push(element);
    }
    while ((element = argvs.shift())) {
        runCommand.push(element);
    }
    return runCommand.join(SPACE_CHARACTER);
}

/**
 * Extracts process start from proc.
 *
 */
function getProcStartTime () {
    try {
        const statFile = fs.readFileSync(SELF_PROC_DIR + STAT);
        if (!statFile) {
            return null;
        }
        const lines = statFile.toString().split(NEW_LINE_SEPERATOR);
        const statData = lines[0];
        if (statData) {
            const statArray = statData.split(SPACE_SEPERATOR_REGEX);
            if (statArray.length >= 21) {
                return statArray[21];
            }
        }
    } catch (err) {
    }
}

/**
 * Sets version of current build
 *
 * @param {String} agentDir
 * @param {ApplicationInfo} applicationInfo
 */
function setBuildDetails (agentDir, applicationInfo) {
    const jsonFileHandler = new JsonHandler(PACKAGE_JSON_FILE, agentDir);
    const pkg = jsonFileHandler.getJSON();
    applicationInfo.collectorVersion = pkg.version;
    applicationInfo.jsonVersion = pkg.jsonVersion;
    applicationInfo.buildNumber = pkg.version;
}

function isK8S () {
    const k8sHost = process.env.KUBERNETES_SERVICE_HOST;
    if (k8sHost) {
        return k8sHost;
    }
    return false;
}

function getHostName () {
    try {
        return OS.hostname();
    } catch (err) {
        return EMPTY_STRING;
    }
}


function getPodNameSpace () {
    try {
        const namespaceFile = fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/namespace');
        return namespaceFile.toString('utf-8');
    } catch (err) {
        return EMPTY_STRING;
    }
}

function isECSEnv () {
    if (process.env.AWS_EXECUTION_ENV === 'AWS_ECS_FARGATE') {
        return true;
    }
    return false;
}

function getECSTaskId () {
    let lines, index;
    try {
        const cgroupFile = fs.readFileSync(CGROUP_FILE_NAME);
        lines = cgroupFile.toString().split(NEW_LINE_SEPERATOR);
        for (const st of lines) {
            index = st.lastIndexOf(ECS_DIR);
            if (index > -1) {
                return st.substring(index + 4, st.lastIndexOf(DIR_IDENTIFIER));
            }
        }
    } catch (err) {
        return EMPTY_STRING;
    }
    return EMPTY_STRING;
}

function populateECSInfo (ecsObj) {
    ecsObj.ecsTaskId = getECSTaskId();
    const ecsData = getECSInfo();
    if (!_.isEmpty(ecsData)) {
        const imageId = ecsData.ImageID;
        const imageName = ecsData.Image;

        ecsObj.imageId = imageId;
        ecsObj.imageName = imageName;

        const labels = ecsData.Labels;

        if (!_.isEmpty(labels)) {
            const containerName = labels['com.amazonaws.ecs.container-name'];
            const ecsTaskDefinitionFamily = labels['com.amazonaws.ecs.task-definition-family'];
            const ecsTaskDefinitionVersion = labels['com.amazonaws.ecs.task-definition-version'];

            ecsObj.containerName = containerName;
            if (ecsTaskDefinitionFamily && ecsTaskDefinitionVersion) {
                ecsObj.ecsTaskDefinition = ecsTaskDefinitionFamily + ':' + ecsTaskDefinitionVersion;
            }
        }
    }
    return ecsObj;
}

function getECSInfo () {
    const url = process.env.ECS_CONTAINER_METADATA_URI;
    let json = {};
    const request = require('sync-request');
    try {
        const res = request('GET', url);
        const body = res.getBody();
        json = JSON.parse(body);
    } catch (error) {
    }
    return json;
}

function getApplicationSHAAndSizeFromWorker (applicationInfo, applicationPath) {
    const { Worker } = require('worker_threads');
    return new Promise((resolve, reject) => {
        const worker = new Worker(
            __dirname + '/sha_worker.js', { workerData: applicationInfo });
        worker.on('message', resolve);
        worker.postMessage(applicationPath);
        worker.on('error', reject);
        worker.on('exit', (code) => {
            if (code !== 0) {
                reject(new Error(
                    `Stopped the Worker Thread of SHA256 with the exit code: ${code}`));
            }
        });
    });
}

function buildIdentifier (identifier) {
    try {
        identifier.nodeId =  EMPTY_STRING;
        identifier.id =  EMPTY_STRING;
        identifier.nodeIp = EMPTY_STRING;
        identifier.nodeName =  NRAgent ? NRAgent.config.process_host.display_name: EMPTY_STRING;
        identifier.collectorIp = localIpAddress();
    } catch (e) {
        logger.error(e);
    }
    return identifier;
}

function setHostProperties () {
    const hostProp = {};
    try {
        hostProp.name = getHostName();
        hostProp.creationTimestamp = new Date().getTime();
        hostProp.state = "Running";
        hostProp.os = process.platform;
        hostProp.arch = process.arch;
        hostProp.version = OS.release();
        hostProp.buildNumber = OS.release();
        hostProp.ipAddress = localIpAddress();
    } catch (e) {
        logger.error(e);
    }

    return hostProp;
}

function setContainerProperties (identifier) {
    const containerProp = require("./ContainerProperties").getInstance();
    try {
        containerProp.id = identifier.id;
        containerProp.name = getHostName();
        containerProp.ipAddress = identifier.collectorIp;
        containerProp.creationTimestamp = new Date().getTime();
        logger.debug("containerProp", containerProp);
    } catch (e) {
        logger.error(e);
    }
    return containerProp;
}

function setPodProperties (identifier, containerProp) {
    const podProp = require("./PodProperties").getInstance();
    try {
        podProp.id = identifier.id;
        podProp.ipAddress = identifier.collectorIp;
        podProp.namespace = getPodNameSpace();
        podProp.name = getHostName();
        podProp.creationTimestamp = new Date().getTime();
        podProp.containerProperties.push(containerProp);
        logger.debug("podProp:", podProp);
    } catch (e) {
        logger.error(e);
    }
    return podProp;
}

function setECSProperties (identifier) {
    let ecsObj = {};
    const ecsProp = require('./ECSProperties').getInstance();
    ecsObj = populateECSInfo(ecsObj);
    try {
        ecsProp.id = ecsObj.ecsTaskId;
        ecsProp.ipAddress = identifier.collectorIp;
        ecsProp.creationTimestamp = new Date().getTime();
        ecsProp.imageId = ecsObj.imageId;
        ecsProp.imageName = ecsObj.imageName;
        ecsProp.containerName = ecsObj.containerName;
        ecsProp.containerId = '';
        ecsProp.ecsTaskDefinition = ecsObj.ecsTaskDefinition;
    } catch (e) {
        logger.error(e);
    }
    return ecsProp;
}

module.exports = {
    getInstance,
    addProperty,
    eventEmitter,
    finalize,
    finalized,
    setBuildDetails,
    getCmdLine
}
;
