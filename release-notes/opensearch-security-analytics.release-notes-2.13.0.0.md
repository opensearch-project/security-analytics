## Version 2.13.0.0 2024-03-19

Compatible with OpenSearch 2.13.0

### Maintenance
* Increment to 2.13. ([#913](https://github.com/opensearch-project/security-analytics/pull/913))
* Add goyamegh as a maintainer (#[868](https://github.com/opensearch-project/security-analytics/pull/868)) (#[899](https://github.com/opensearch-project/security-analytics/pull/899))

### Features
* Findings api enhancements (#[914](https://github.com/opensearch-project/security-analytics/pull/914)) (#[795](https://github.com/opensearch-project/security-analytics/issues/795))
* Get all findings as part of findings API enhancement (#[803](https://github.com/opensearch-project/security-analytics/pull/803))
* Support object fields in aggregation based sigma rules (#[789](https://github.com/opensearch-project/security-analytics/pull/789))

### Bug Fixes
* Fix get mappings view API incorrectly returning ecs path (#[867](https://github.com/opensearch-project/security-analytics/pull/867)) (#[905](https://github.com/opensearch-project/security-analytics/pull/905)) (#[866](https://github.com/opensearch-project/security-analytics/issues/866))
* Add an "exists" check for "not" condition in sigma rules (#[852](https://github.com/opensearch-project/security-analytics/pull/852)) (#[897](https://github.com/opensearch-project/security-analytics/pull/897))
* Fix duplicate ecs mappings which returns incorrect log index field in mapping view API (#[786](https://github.com/opensearch-project/security-analytics/pull/786)) (#[788](https://github.com/opensearch-project/security-analytics/pull/788)) (#[898](https://github.com/opensearch-project/security-analytics/pull/898))
* ArrayIndexOutOfBoundsException for inconsistent detector index behavior (#[843](https://github.com/opensearch-project/security-analytics/pull/843)) (#[858](https://github.com/opensearch-project/security-analytics/pull/852))
* Fail the flow when detector type is missing in the log types index (#[845](https://github.com/opensearch-project/security-analytics/pull/845)) (#[857](https://github.com/opensearch-project/security-analytics/pull/857))
* Remove blocking calls and change threat intel feed flow to event driven (#[871](https://github.com/opensearch-project/security-analytics/pull/871)) (#[876](https://github.com/opensearch-project/security-analytics/pull/876))
* Fixes OCSF integ test (#[918](https://github.com/opensearch-project/security-analytics/pull/918))
* Pass rule field names in doc level queries during monitor/creation. Remove blocking actionGet() calls (#[873](https://github.com/opensearch-project/security-analytics/pull/873))
* Add search request timeouts for correlations workflows (#[893](https://github.com/opensearch-project/security-analytics/pull/893)) (#[901](https://github.com/opensearch-project/security-analytics/pull/893)) (#[879](https://github.com/opensearch-project/security-analytics/issues/879)])

### Refactor
* Refactor invocation of Action listeners in correlations (#[880](https://github.com/opensearch-project/security-analytics/issues/879)) (#[900](https://github.com/opensearch-project/security-analytics/issues/879)) (#[879](https://github.com/opensearch-project/security-analytics/issues/879)])

### Documentation
* Added 2.13.0 release notes (#[945](https://github.com/opensearch-project/security-analytics/pull/945))