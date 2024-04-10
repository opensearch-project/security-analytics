## Version 2.10.0.0 2023-09-07

Compatible with OpenSearch 2.10.0

### Maintenance
* Bump version to 2.10 and resolve compile issues ([#521](https://github.com/opensearch-project/security-analytics/pull/521))

### Features
* Custom log type implementation ([#500](https://github.com/opensearch-project/security-analytics/pull/500))
* add mitre attack based auto-correlations support in correlation engine ([#532](https://github.com/opensearch-project/security-analytics/pull/532))
* Using alerting workflows in detectors ([#541](https://github.com/opensearch-project/security-analytics/pull/541))

### Bug Fixes
* Fix for mappings of custom log types & other bug fixes ([#505](https://github.com/opensearch-project/security-analytics/pull/505))
* Fixes detectorType incompatibility with detector rules ([#524](https://github.com/opensearch-project/security-analytics/pull/524))

### Refactoring
* Fix google-java-format-1.17.0.jar: 1 vulnerabilities ([#526](https://github.com/opensearch-project/security-analytics/pull/526))
* segment replication changes ([#529](https://github.com/opensearch-project/security-analytics/pull/529))
* Use core OpenSearch version of commons-lang3 ([#535](https://github.com/opensearch-project/security-analytics/pull/535))
* Force google guava to 32.0.1 ([#536](https://github.com/opensearch-project/security-analytics/pull/536))
* Updates demo certs used in integ tests ([#543](https://github.com/opensearch-project/security-analytics/pull/543))

### Documentation
* Added 2.10.0 release notes. ([#555](https://github.com/opensearch-project/security-analytics/pull/555))