## Version 2.18.0.0 2024-10-28

Compatible with OpenSearch 2.18.0

### Maintenance
* Incremented version to 2.18.0 ([#1314](https://github.com/opensearch-project/security-analytics/pull/1314))
* update to lucene 9.12 ([#1349](https://github.com/opensearch-project/security-analytics/pull/1349))

### Refactoring
* separate doc-level monitor query indices created by detectors ([#1324](https://github.com/opensearch-project/security-analytics/pull/1324))
* update number of replicas of system indices to 1-20 and number of primary shards for system indices to 1 ([#1358](https://github.com/opensearch-project/security-analytics/pull/1358))
* update min number of replicas to 0 ([#1364](https://github.com/opensearch-project/security-analytics/pull/1364))
* updated dedicated query index settings to true ([#1365](https://github.com/opensearch-project/security-analytics/pull/1365))
* set the refresh policy to IMMEDIATE when updating correlation alerts ([#1382](https://github.com/opensearch-project/security-analytics/pull/1382))

### Bug Fixes
* remove redundant logic to fix OS launch exception and updates actions/upload-artifac2 to @V3 ([#1303](https://github.com/opensearch-project/security-analytics/pull/1303))
* Add null check while adding fetched iocs into per-indicator-type map ([#1335](https://github.com/opensearch-project/security-analytics/pull/1335))
* Fix notifications listener leak in threat intel monitor ([#1361](https://github.com/opensearch-project/security-analytics/pull/1361))
* [Bug] Fixed ListIOCs number of findings cap. ([#1373](https://github.com/opensearch-project/security-analytics/pull/1373))
* [Bug] Add exists check for IOCs index. ([#1392](https://github.com/opensearch-project/security-analytics/pull/1392))

### Documentation
* Added 2.18.0 release notes. ([#]())