## Version 2.16.0.0 2024-07-23

Compatible with OpenSearch 2.16.0

### Features
* Threat Intel Analytics ([#1098](https://github.com/opensearch-project/security-analytics/pull/1098))

### Maintenance
* Incremented version to 2.16.0. ([#1197](https://github.com/opensearch-project/security-analytics/pull/1197))
* Fix build CI error due to action runner env upgrade node 20 ([#1143](https://github.com/opensearch-project/security-analytics/pull/1143))

### Enhancement
* added correlationAlert integ tests ([#1099](https://github.com/opensearch-project/security-analytics/pull/1099))
* add filter to list ioc api to fetch only from available and refreshing apis. null check for alias of ioc indices ([#1131](https://github.com/opensearch-project/security-analytics/pull/1131))
* Changes threat intel default store config model ([#1133](https://github.com/opensearch-project/security-analytics/pull/1133))
* adds new tif source config type - url download ([#1142](https://github.com/opensearch-project/security-analytics/pull/1142))

### Bug Fixes
* pass integ tests ([#1082](https://github.com/opensearch-project/security-analytics/pull/1082))
* set blank response when indexNotFound exception ([#1125](https://github.com/opensearch-project/security-analytics/pull/1125))
* throw error when no iocs are stored due to incompatible ioc types from S3 downloaded iocs file ([#1129](https://github.com/opensearch-project/security-analytics/pull/1129))
* fix findingIds filter on ioc findings search api ([#1130](https://github.com/opensearch-project/security-analytics/pull/1130))
* Adjusted IOCTypes usage ([#1156](https://github.com/opensearch-project/security-analytics/pull/1156))
* Fix the job scheduler parser, action listeners, and multi-node test ([#1157](https://github.com/opensearch-project/security-analytics/pull/1157))
* ListIOCs API to return number of findings per IOC ([#1163](https://github.com/opensearch-project/security-analytics/pull/1163))
* Ioc upload integ tests and fix update ([#1162](https://github.com/opensearch-project/security-analytics/pull/1162))
* [BUG] Resolve aliases in monitor input to concrete indices before computing ioc-containing fields from concrete index docs ([#1173](https://github.com/opensearch-project/security-analytics/pull/1173))
* Enum fix ([#1178](https://github.com/opensearch-project/security-analytics/pull/1178))
* fix bug: threat intel monitor finding doesnt contain all doc_ids containing malicious IOC ([#1184](https://github.com/opensearch-project/security-analytics/pull/1184))
* Fixed bulk indexing for IOCs ([#1187](https://github.com/opensearch-project/security-analytics/pull/1187))
* Fix ioc upload update behavior and change error response ([#1192](https://github.com/opensearch-project/security-analytics/pull/1192))
* Catch and wrap exceptions. ([#1198](https://github.com/opensearch-project/security-analytics/pull/1198))

### Documentation
* Added 2.16.0 release notes. ([#1196](https://github.com/opensearch-project/security-analytics/pull/1196))