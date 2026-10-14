## Version 2.19.7 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 2.19.7

### Bug Fixes

* Fix authorization bypass in stashContext() by adding pre-flight index permission checks and blocking cross-index terms lookup queries ([#1768](https://github.com/opensearch-project/security-analytics/pull/1768))

### Infrastructure

* Only use alerting SNAPSHOTS in SNAPSHOT builds, otherwise use release artifacts ([#1841](https://github.com/opensearch-project/security-analytics/pull/1841))

### Maintenance

* Add Eclipse P2 mirror to avoid download.eclipse.org outages ([#1801](https://github.com/opensearch-project/security-analytics/pull/1801))
* Guard eclipse() to Spotless tasks and keep P2 mirror on pinned version ([#1809](https://github.com/opensearch-project/security-analytics/pull/1809))
* Bump 1password/load-secrets-action to v5.0.1 ([#1795](https://github.com/opensearch-project/security-analytics/pull/1795))
