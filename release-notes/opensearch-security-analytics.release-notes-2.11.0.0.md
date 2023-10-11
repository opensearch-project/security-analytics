## Version 2.11.0.0 2023-10-11

Compatible with OpenSearch 2.11.0

### Maintenance
* Bump version to 2.11. ([#631](https://github.com/opensearch-project/security-analytics/pull/631))

### Enhancements
* Adds support for alerts and triggers on group by based sigma rules. ([#545](https://github.com/opensearch-project/security-analytics/pull/545))
* Auto expand replicas. ([#547](https://github.com/opensearch-project/security-analytics/pull/547))
* Auto expand replicas for logtype index. ([#568](https://github.com/opensearch-project/security-analytics/pull/568))
* Adding WAF Log type. ([#617](https://github.com/opensearch-project/security-analytics/pull/617))
* Add category to custom log types. ([#634](https://github.com/opensearch-project/security-analytics/pull/634))

### Refactoring
* Address search request timeouts as transient error. ([#561](https://github.com/opensearch-project/security-analytics/pull/561))
* Change ruleId if it exists. ([#628](https://github.com/opensearch-project/security-analytics/pull/628))

### Bug Fixes
* Fixes verifying workflow test when security is enabled. ([#563](https://github.com/opensearch-project/security-analytics/pull/563))
* Fix flaky integration tests. ([#581](https://github.com/opensearch-project/security-analytics/pull/581))
* Sigma Aggregation rule fixes. ([#622](https://github.com/opensearch-project/security-analytics/pull/622))

### Infrastructure
* Ignore tests that may be flaky. ([#596](https://github.com/opensearch-project/security-analytics/pull/596))

### Documentation
* Added 2.11.0 release notes. ([#]())