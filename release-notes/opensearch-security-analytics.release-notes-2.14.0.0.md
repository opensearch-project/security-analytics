## Version 2.14.0.0 2024-04-30

Compatible with OpenSearch 2.14.0

### Maintenance
* Increment version to 2.14.0-SNAPSHOT. ([#1007](https://github.com/opensearch-project/security-analytics/pull/1007))
* Updates sample cert and admin keystore ([#864](https://github.com/opensearch-project/security-analytics/pull/864))

### Features
* Add latest sigma rules ([#942](https://github.com/opensearch-project/security-analytics/pull/942))

### Bug Fixes
* Fix integ tests after add latest sigma rules ([#950](https://github.com/opensearch-project/security-analytics/pull/950))
* Fix keywords bug and add comments ([#964](https://github.com/opensearch-project/security-analytics/pull/964))
* Changes doc level query name field from id to rule name and adds validation ([#972](https://github.com/opensearch-project/security-analytics/pull/972))
* Fix check for agg rules in detector trigger condition to create chained findings monitor ([#992](https://github.com/opensearch-project/security-analytics/pull/992))

### Refactoring
* Allow detectors to be stopped if underlying workflow is deleted. Don't allow them to then be started/edited ([#810](https://github.com/opensearch-project/security-analytics/pull/810))

### Documentation
* Added 2.14.0 release notes. ([#]())