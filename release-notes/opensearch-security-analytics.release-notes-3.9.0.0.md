## Version 3.9.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.9.0

### Features

* Onboard security-analytics plugin to centralized resource authorization ([#1735](https://github.com/opensearch-project/security-analytics/pull/1735))
* Register detector and correlation-rule indices as system indices for resource-sharing framework support ([#1749](https://github.com/opensearch-project/security-analytics/pull/1749))

### Bug Fixes

* Fix authorization bypass via stashContext() by adding pre-flight index permission checks and blocking cross-index terms lookup queries ([#1760](https://github.com/opensearch-project/security-analytics/pull/1760))

### Infrastructure

* Fix code coverage upload action ([#1810](https://github.com/opensearch-project/security-analytics/pull/1810))

### Maintenance

* Rename resource sharing feature flag to the non-experimental key ([#1815](https://github.com/opensearch-project/security-analytics/pull/1815))
* Switch from snakeyaml to snakeyaml-engine for YAML processing ([#1812](https://github.com/opensearch-project/security-analytics/pull/1812))
