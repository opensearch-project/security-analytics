## Version 3.10.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.10.0

### Enhancements

* Deprecate `filter_by_backend_roles` setting, targeting removal in 4.0 in favor of resource sharing and access control ([#1818](https://github.com/opensearch-project/security-analytics/pull/1818))

### Bug Fixes

* Guard against null and immutable map returns in RuleIndices and CustomLogType to prevent NPE and UnsupportedOperationException ([#1797](https://github.com/opensearch-project/security-analytics/pull/1797))
* Resolve index template by backing index for index-alias mappings to prevent component templates from attaching to the wrong template ([#1835](https://github.com/opensearch-project/security-analytics/pull/1835))
* Get alerts of all accessible detectors with server-side paging, sorting, and filtering instead of loading all alerts client-side ([#1837](https://github.com/opensearch-project/security-analytics/pull/1837))

### Maintenance

* Retrieve jackson-databind version from core ([#1819](https://github.com/opensearch-project/security-analytics/pull/1819))
* Bump jackson-databind to 2.18.8 to remediate five CVEs ([#1828](https://github.com/opensearch-project/security-analytics/pull/1828))
