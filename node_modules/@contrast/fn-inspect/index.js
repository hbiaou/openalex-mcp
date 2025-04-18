'use strict';

const binding = require('node-gyp-build')(__dirname);

module.exports = {
  /**
   * Retrieves name, type, column, lineNumber and file from a function reference
   *
   * @param {Function} fn function reference to obtain info
   * @return {FunctionInfo | null}
   */
  funcInfo(fn) {
    const info = binding.funcInfo(fn);
    if (info === null) return null;

    info.type = fn.constructor.name;
    return info;
  },
};
