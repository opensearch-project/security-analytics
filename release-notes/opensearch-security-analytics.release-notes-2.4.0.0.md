## Version 2.4.0.0 Release Notes

Compatible with OpenSearch 2.4.0
Initial release of `opensearch-security-analytics` plugin

### Features

* Sigma Rules, Rule Engine Parser ([#6](https://github.com/opensearch-project/security-analytics/pull/6), [#8](https://github.com/opensearch-project/security-analytics/pull/8), [#26](https://github.com/opensearch-project/security-analytics/pull/26), [#27](https://github.com/opensearch-project/security-analytics/pull/27))
* Threat Detector Lifecycle Management (CRUD), Pre-packaged/Custom Rule Lifecycle Management (CRUD) ([#32](https://github.com/opensearch-project/security-analytics/pull/32), [#40](https://github.com/opensearch-project/security-analytics/pull/40), [#43](https://github.com/opensearch-project/security-analytics/pull/43), [#48](https://github.com/opensearch-project/security-analytics/pull/48), [#52](https://github.com/opensearch-project/security-analytics/pull/52), [#80](https://github.com/opensearch-project/security-analytics/pull/80))
* Mapping Logs/Rule fields to ECS(Elastic Common Schema) format ([#30](https://github.com/opensearch-project/security-analytics/pull/30), [#35](https://github.com/opensearch-project/security-analytics/pull/35), [#46](https://github.com/opensearch-project/security-analytics/pull/46), [#46](https://github.com/opensearch-project/security-analytics/pull/46), [#89](https://github.com/opensearch-project/security-analytics/pull/89))
* Integrate Findings (Lifecycle Management including Rollovers), Triggers, Alerts(Lifecycle Management) ([#39](https://github.com/opensearch-project/security-analytics/pull/39), [#54](https://github.com/opensearch-project/security-analytics/pull/54), [#67](https://github.com/opensearch-project/security-analytics/pull/67), [#70](https://github.com/opensearch-project/security-analytics/pull/70), [#70](https://github.com/opensearch-project/security-analytics/pull/70), [#82](https://github.com/opensearch-project/security-analytics/pull/82))
* Integrate with Notifications, Acknowledge Alerts ([#71](https://github.com/opensearch-project/security-analytics/pull/71), [#75](https://github.com/opensearch-project/security-analytics/pull/75), [#85](https://github.com/opensearch-project/security-analytics/pull/85))
* Integrate with Security, implement RBAC, backend roles filtering ([#78](https://github.com/opensearch-project/security-analytics/pull/78))

### Enhancements

* Use of `custom datasources while creating alerting monitors` in `opensearch-security-analytics` ([#34](https://github.com/opensearch-project/security-analytics/pull/34), [#72](https://github.com/opensearch-project/security-analytics/pull/72), [#99](https://github.com/opensearch-project/security-analytics/pull/99))
* add owner field in monitor to seggregate `opensearch-security-analytics` specific data from `opensearch-alerting` data. ([#110](https://github.com/opensearch-project/security-analytics/pull/110))

### Bug Fixes

* fix bug to support aliasMappings in create mappings api ([#69](https://github.com/opensearch-project/security-analytics/pull/69))
* fix for multi-node test faiures on rule ingestion ([#76](https://github.com/opensearch-project/security-analytics/pull/76))
* fix bug on deleting/updating rule when it is not used by detectors ([#77](https://github.com/opensearch-project/security-analytics/pull/77))
* fix build for delete detector api ([#97](https://github.com/opensearch-project/security-analytics/pull/97))
* findingsDto assign detectorId bug ([#102](https://github.com/opensearch-project/security-analytics/pull/102))
* update index monitor method to include namedWriteableRegistry for common utils interface ([#105](https://github.com/opensearch-project/security-analytics/pull/105))

### Infrastructure

* Initial commit for setting up the `opensearch-security-analytics` plugin ([#3](https://github.com/opensearch-project/security-analytics/pull/3))
* Add support for windows builds ([#84](https://github.com/opensearch-project/security-analytics/pull/84))
* Add backport workflow in GitHub workflows ([#93](https://github.com/opensearch-project/security-analytics/pull/93), [#113](https://github.com/opensearch-project/security-analytics/pull/113))
* Change `groupid` in `build.gradle` ([#91](https://github.com/opensearch-project/security-analytics/pull/91))
* Add `build.sh` to generate `maven artifacts` ([#87](https://github.com/opensearch-project/security-analytics/pull/87))

### Documentation

* Update `README` ([#1](https://github.com/opensearch-project/security-analytics/pull/1))
* Add `MAINTAINERS.md` file ([#83](https://github.com/opensearch-project/security-analytics/pull/83))