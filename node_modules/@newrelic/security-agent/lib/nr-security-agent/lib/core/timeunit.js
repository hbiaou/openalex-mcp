
/*
 * Copyright 2023 New Relic Corporation. All rights reserved.
 * SPDX-License-Identifier: New Relic Software License v1.0
 */


/**
 * Creates TimeUnit Instance with milliseconds
 * as the base unit. 
 */
function TimeUnit() {
    this.MILLISECONDS = 1;
    this.NANOSECONDS = 0.000001
    this.MICROSECONDS = 0.001;
    this.SECONDS = 1000;
    this.MINUTES = 60000;
    this.HOURS = 3600000;
    this.DAY = 86400000;

    /**
     * converts time value from given unit.
     * 
     * @param {Number} value
     * @param {String} timeunit
     * 
     * @returns milliseconds
     * 
     */
    this.getMillis = function (value, unit, valueOnFail) {
        const UNIT = unit.toString().toUpperCase();
        if (this[UNIT]) {
            try {
                return value * this[UNIT];
            } catch (e) {

            }
        }
        return valueOnFail;
    }
}

module.exports = new TimeUnit();

