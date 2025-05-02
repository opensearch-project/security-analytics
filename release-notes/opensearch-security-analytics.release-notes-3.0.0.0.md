## Version 3.0.0.0 2025-05-01

Compatible with OpenSearch 3.0.0

### Maintenance
* Increment version to 3.1.0-SNAPSHOT ([#1517](https://github.com/opensearch-project/security-analytics/pull/1517))
* Remove beta1 qualifier ([#1519](https://github.com/opensearch-project/security-analytics/pull/1519))
* Using java-agent gradle plugin to phase off Security Manager in favor of Java-agent. ([#1505](https://github.com/opensearch-project/security-analytics/pull/1505))
* Fix build due to phasing off SecurityManager usage in favor of Java Agent ([#1504](https://github.com/opensearch-project/security-analytics/pull/1504))
* [Release 3.0] Add alpha1 qualifier. ([#1490](https://github.com/opensearch-project/security-analytics/pull/1490))
* Updated commons jar with CVE fixes. ([#1481](https://github.com/opensearch-project/security-analytics/pull/1481))
* Update gradle 8.10.2 and support jdk23 ([#1492](https://github.com/opensearch-project/security-analytics/pull/1492))
* Fix security-enabled test workflow for 3.0-alpha1. ([#1494](https://github.com/opensearch-project/security-analytics/pull/1494/))
* Update version qualifier to beta1. ([#1500](https://github.com/opensearch-project/security-analytics/pull/1500))

### Features
* Adds support for uploading threat intelligence in Custom Format ([#1493](https://github.com/opensearch-project/security-analytics/pull/1493))

### Bug Fixes
* Remove usage of deprecated batchSize() method ([#1503](https://github.com/opensearch-project/security-analytics/pull/1503))
* Refactored flaky test. ([#1467](https://github.com/opensearch-project/security-analytics/pull/1467))
* Remove overrides of preserveIndicesUponCompletion ([#1498](https://github.com/opensearch-project/security-analytics/pull/1498))

### Documentation
* Added 3.0.0 release notes. ([#1523](https://github.com/opensearch-project/security-analytics/pull/1523))
