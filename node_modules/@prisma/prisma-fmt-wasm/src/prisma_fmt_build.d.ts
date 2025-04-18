/* tslint:disable */
/* eslint-disable */
/**
* @param {string} schema
* @param {string} params
* @returns {string}
*/
export function format(schema: string, params: string): string;
/**
* Docs: https://prisma.github.io/prisma-engines/doc/prisma_fmt/fn.get_config.html
* @param {string} params
* @returns {string}
*/
export function get_config(params: string): string;
/**
* Docs: https://prisma.github.io/prisma-engines/doc/prisma_fmt/fn.get_dmmf.html
* @param {string} params
* @returns {string}
*/
export function get_dmmf(params: string): string;
/**
* @param {string} input
* @returns {string}
*/
export function lint(input: string): string;
/**
* @param {string} params
*/
export function validate(params: string): void;
/**
* @param {string} input
* @returns {string}
*/
export function native_types(input: string): string;
/**
* @param {string} input
* @returns {string}
*/
export function referential_actions(input: string): string;
/**
* @returns {string}
*/
export function preview_features(): string;
/**
* The API is modelled on an LSP [completion
* request](https://github.com/microsoft/language-server-protocol/blob/gh-pages/_specifications/specification-3-16.md#textDocument_completion).
* Input and output are both JSON, the request being a `CompletionParams` object and the response
* being a `CompletionList` object.
* @param {string} schema
* @param {string} params
* @returns {string}
*/
export function text_document_completion(schema: string, params: string): string;
/**
* This API is modelled on an LSP [code action
* request](https://github.com/microsoft/language-server-protocol/blob/gh-pages/_specifications/specification-3-16.md#textDocument_codeAction=).
* Input and output are both JSON, the request being a
* `CodeActionParams` object and the response being a list of
* `CodeActionOrCommand` objects.
* @param {string} schema
* @param {string} params
* @returns {string}
*/
export function code_actions(schema: string, params: string): string;
/**
* Trigger a panic inside the wasm module. This is only useful in development for testing panic
* handling.
*/
export function debug_panic(): void;
