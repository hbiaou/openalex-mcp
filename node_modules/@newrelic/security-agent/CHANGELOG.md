### v2.4.0 (2025-03-21)
#### Features
* Support for gRPC error reporting
* Support to detect API endpoints in next.js framework 
#### Miscellaneous chores
* Updated axios to v1.8.4

### v2.3.2 (2025-03-11)
#### Bug fixes
* Updated axios to v1.8.2 
#### Miscellaneous chores
* Updated readme 


### v2.3.1 (2025-02-04)
#### Bug fixes
* Removed docker-cli-js dependency and updated mongodb unit test case (#283)
* Added safety check for agentModule before accessing its properties (#284)

### v2.3.0 (2025-02-03)
#### Features
* Added Support for VM module
* IAST support for Next.js
* Support for Insecure settings i.e crypto, hash and random modules 

#### Bug fixes
* Fix for special characters in ws header
* Fix for getting transaction in graphql instrumentation 
* Fix for mongodb unit tests 

#### Miscellaneous chores
* deps-dev: bump undici from v5.28.4 to v5.28.5
* Updated axios to v1.7.9 

### v2.2.0 (2024-12-18)
#### Features
* Support for express 5.x 
* IAST support for GraphQL
* Added support for trustboundary security events

#### Bug fixes
* Fix for empty route in fastify

### v2.1.1 (2024-11-07)
#### Bug fixes
* Fix for assignment to logger constant 

### v2.1.0 (2024-11-05)
#### Features
* IAST support for CI/CD
* Support for IAST schedule, delay and ignore scan categories
#### Bug fixes
* Added default values for scan_schedule, scan_controllers and exclude_from_iast_scan config
* Fix for security home placeholder replacement in fuzz requests
* Handling to not resolve file path in fs module instrumentation
* Fix for batch size and condition of iast-data-request sending 
#### Miscellaneous chores
* Added requestURI field in http request for application-runtime-error
* Updated instrumented to get the transaction directly instead of from the active segment

### v2.0.0 (2024-09-20)
### ⚠ BREAKING CHANGES
* Dropped support for Node.js v16
* Dropped functionality to generate snapshot file
#### Features
* Support to honour proxy settings via config
* Support for secure cookie security event generation
* Report error to Error Inbox upon connection failure to Security Engine
* Support to detect application and server path
* Functionality to truncate Incoming HTTP request upto default limit
* Dropped support for Node.js v16
* Dropped functionality to generate snapshot file
#### Bug fixes
* Handling for empty data in IAST fuzzing header
* Added identifiers in events
* Fix for file integrity security event generation
* Fix for missing identifiers in iast-data-request JSON

### v1.5.0 (2024-08-14)
#### Features
* Support for Node.js v22.x
#### Bug fixes
* Fix for traceId in error reporting
#### Miscellaneous chores
* (deps): bumped axios from 1.6.8 to 1.7.4 
* (deps-dev): bumped ws from 7.5.9 to 8.18.0
#### Continuous integration
* Added Node.js v22.x to unit tests

### v1.4.0 (2024-06-24)
#### Features
* Added support to report application's errors while IAST scanning
* Support to detect gRPC API endpoints 
#### Bug fixes
* Remove additional headers added by IAST client
* Fix for uncaught exception reporting 
#### Miscellaneous chores
* Updated package.json to bump ws from 8.14.2 to 8.17.1 
* (deps-dev): bump @grpc/grpc-js from 1.9.12 to 1.10.9 
* (deps-dev): bump braces from 3.0.2 to 3.0.3
* (deps): bump ws from 8.14.2 to 8.17.1 

### v1.3.0 (2024-05-31)
#### Features
* Added route field in security event for API endpoint mapping
#### Bug fixes
* Fix for control commands acknowledgement in security agent 
* Added assert for typeof response data in Reflected XSS validation 
* Updated @grpc/grpc-js instrumentation to instrument submodules 
* Handling to convert header values into string
#### Miscellaneous chores
* Updated log level for critical messages 
* Readme update
* (deps-dev): bump axios from 0.21.4 to 1.7.2

### v1.2.0 (2024-04-12)
#### Features
* Added instrumentation for express framework's res.download() and res.sendFile()
#### Bug fixes
* Handling to decrypt fuzz header data for IAST scanning 
* Logging and snapshot file fixes
#### Miscellaneous chores
* Prepend vulnerability case type with apiId
* Updated jsonVersion to v1.2.0
* Bumped undici from 5.28.3 to 5.28.4

### v1.1.1 (2024-03-21)
#### Bug fixes
* Reverted IAST support for gRPC.

### v1.1.0 (2024-03-19)
#### Features
* IAST support for grpc 
* Functionality to report API endpoints of the application
* IAST support for undici
#### Bug fixes
* Updated permissions for file/directory created by security agent
#### Miscellaneous chores
* Bumped follow-redirects from v1.15.2 to v1.15.4  
* Updated axios to v1.6.8
* Bumped ip from v2.0.0 to v2.0.1
* Bumped undici from 5.28.2 to v5.28.3
* Readme update

### v1.0.1 (2024-02-07)
#### Bug fixes
* Reporting of framework in security event json 
#### Miscellaneous chores
* Updated software license to New Relic Software License Version 1.0
* Ability to send critical messages on successful startup of agent
* Updated Copyright headers
* Updated license in readme

### v0.7.0 (2024-01-18)
#### Features
* Handling to exclude unsupported content types from rxss processing
* Handling to report errors/critical messages to Security Engine
#### Bug fixes
* Fix for file operation event's parameter must be absolute path of file
* Fix for ReferenceError of commonUtils module
#### Miscellaneous chores
* Updated log event jsonName to "critical-messages"
* Removed dependency @aws-sdk/client-lambda
* Bumped follow-redirects from v1.15.2 to v1.15.4  
* Upgraded axios to v1.6.5 

### v0.6.0 (2024-01-03)
#### Features
* Added ws headers NR-CSEC-ENTITY-GUID and NR-CSEC-ENTITY-NAME
* Updated jsonVersion to 1.1.1 in security events
* Support to send important logs/errors to security engine
#### Bug fixes
* Added missing protocol in http request object
* Fix for honouring probing interval from policy
#### Miscellaneous chores
* Added nestjs test cases
* Additional logging for instrumented modules and methods 
* Upgraded axios to v1.6.3
* Removed pinned version for axios and check-disk-space
* Update in lockfileVersion of package-lock.json
* Updated @babel/traverse, protobufjs, fast-xml-parser and @aws-sdk/credential-providers
* Updated Readme.md


### v0.5.0 (2023-11-17)
#### Features
* IAST support for NestJS framework
#### Bug Fixes
* Fixed misspelled constant in fs.open() hook
* Minor fix in applicationInfo for pod properties
#### Miscellaneous chores
* Upgraded ws to v8.14.2 and updated initialization of websocket for v8.x.
* Upgraded check-disk-space to v3.4.0
* Upgraded @aws-sdk/client-lambda to v3.436.0

### v0.4.0 (2023-10-27)
#### Features
* Added event stats for RASP, IAST and exit events in healthcheck. 
#### Miscellaneous chores
* Deps: Updated uuid to v9.0.1 and @aws-sdk/client-lambda to v3.405.0
* Upgraded axios to 1.6.0 to resolve CVE-2023-45857 
#### Continuous integration
* Removed Node.js 14.x from CI.
* Added should_skip flag to skip CI based on label.

### v0.3.0 (2023-09-25)
#### Features
* Last leg acknowledgement in IAST scanning.
#### Bug Fixes
* Fix for mysql query params in security events.
* Logging update for default log level and status file flags.
* Update in IAST batch size processing.
* Disable instrumentation when security enabled flag is set to false
#### Miscellaneous Chores
* Readme update

### v0.2.1 (2023-08-07)
#### Bug Fixes
* Pinned check-disk-space to v3.3.1 to support Node.js v14
#### Miscellaneous Chores
* deps: Updated semver to v7.5.4 and @aws-sdk/client-lambda to v3.363.0
#### Continuous Integration
* Add Node.js 20.x to CI

### v0.2.0 (2023-07-24)
#### Features
* IAST data pull implementation
* Logging update

#### Bug Fixes
* Param fixes for mysql and file hooks.

### v0.1.3
* Updated semver to v7.5.3 (Fix for CWE-1333)
* Updated request-ip, log4js, html-entities, uuid and fast-safe-stringify to latest version.
* Fix for system call event generation to avoid null parameters in event.
* Fix for id in nr-csec-tracing-data.
* WS logging update.

### v0.1.2
* bump @aws-sdk/client-lambda to v3.348.0
* Minor fix in ws reconnect.

### v0.1.1
* Fix in mysql instrumentation on getConnection to check if callback is wrapped
* NR-123832: Support for fire and forget vulnerability detection
* Fixes for snapshot file.
* Handling for high_security config.
### v0.1.0
* Handling to use OS specific path separator.
* Functionality to create directories in windows environment.
* IAST support for windows.
* Log file permission fix.
### v0.0.8
* Handling for IP resolving to IPV4 as Node.js v17 and above no longer re-sorts results of IP address lookups and returns them as-is.
* Third Party Notices update
* Update in publish workflow
### v0.0.7
* Updated copyright header in source files
* ReadMe update
* Minor logging update
### v0.0.6
* Updated default fuzz host to 0.0.0.0
* Handling to get custom certificate path from config instead of environment variable

### v0.0.5
* Updated README file
* Init logging update
* Code refactoring
* Minor bug fixes