## Version 2.5.0.0 Release Notes
Compatible with OpenSearch 2.5.0

### Maintenance
* Bumped version to 2.5. ([#215](https://github.com/opensearch-project/security-analytics/pull/215))
* Updated MAINTAINERS.md format. ([#240](https://github.com/opensearch-project/security-analytics/pull/240))

### Features
* Implement secure transport action for get alerts and ack alerts. ([#161](https://github.com/opensearch-project/security-analytics/pull/161))
* GetMappingsView API - index pattern/alias/datastream support. ([#245](https://github.com/opensearch-project/security-analytics/pull/245))
* Createmappings api index pattern support. ([#260](https://github.com/opensearch-project/security-analytics/pull/260))

### Bug Fixes
* Fixed aliases being returned in unmapped_index_fields. ([#147](https://github.com/opensearch-project/security-analytics/pull/147))
* Fix vulnerability in yaml constructor. ([#198](https://github.com/opensearch-project/security-analytics/pull/198))
* Fix flaky integration tests for security analytics. ([#241](https://github.com/opensearch-project/security-analytics/pull/241))
* Fixed SecureFindingRestApiIT. Removed uppercasing of the detector type. ([#247](https://github.com/opensearch-project/security-analytics/pull/247))
* Fix ci builds for security-analytics. ([#253](https://github.com/opensearch-project/security-analytics/pull/253))

### Refactoring
* Search returns detector type in CAPS fix and integration tests. ([#174](https://github.com/opensearch-project/security-analytics/pull/174))
* Added dummy search when creating detector on the given indices. ([#197](https://github.com/opensearch-project/security-analytics/pull/197))
* Updated network mappings. ([#211](https://github.com/opensearch-project/security-analytics/pull/211))
* Updated windows mappings. ([#212](https://github.com/opensearch-project/security-analytics/pull/212))
* Updated ad_ldap mappings. ([#213](https://github.com/opensearch-project/security-analytics/pull/213))
* Removed create/delete queryIndex. ([#215](https://github.com/opensearch-project/security-analytics/pull/215))
* Update Linux mappings. ([#223](https://github.com/opensearch-project/security-analytics/pull/223))
* Changes to return empty search response for custom rules. ([#231](https://github.com/opensearch-project/security-analytics/pull/231))
* Service Returns Unhandled Error Response. ([#248](https://github.com/opensearch-project/security-analytics/pull/248))

### Documentation
* Added 2.5 release notes. ([#268](https://github.com/opensearch-project/security-analytics/pull/268))