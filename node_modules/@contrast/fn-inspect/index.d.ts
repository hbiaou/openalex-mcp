/* eslint-disable @typescript-eslint/ban-types */

declare interface FunctionInfo {
  file: string;
  column: number;
  lineNumber: number;
  method: string;
  type: 'AsyncFunction' | 'Function';
}

declare const fnInspect: {
  /** Retrieves name, type, column, lineNumber and file from a function reference */
  funcInfo(fn: Function): FunctionInfo | null;
};

export = fnInspect;
