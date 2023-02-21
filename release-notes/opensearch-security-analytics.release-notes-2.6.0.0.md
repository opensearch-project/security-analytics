## Version 2.6.0.0 Release Notes

Compatible with OpenSearch 2.6.0

### Features
* GetIndexMappings index pattern support. ([#265](https://github.com/opensearch-project/security-analytics/pull/265))
* Added API to fetch all log types/rule categories. ([#327](https://github.com/opensearch-project/security-analytics/pull/327))

### Enhancement
* Adds timestamp field alias and sets time range filter in bucket level monitor. ([#262](https://github.com/opensearch-project/security-analytics/pull/262))
* Update others_application mappings. ([#277](https://github.com/opensearch-project/security-analytics/pull/277))
* Update others_apt mappings. ([#278](https://github.com/opensearch-project/security-analytics/pull/278))
* Index template conflict resolve; GetIndexMappings API changes. ([#283](https://github.com/opensearch-project/security-analytics/pull/283))
* Add nesting level to yaml constructor. ([#286](https://github.com/opensearch-project/security-analytics/pull/286))
* Update others_cloud mappings. ([#301](https://github.com/opensearch-project/security-analytics/pull/301))
* Update others_compliance mappings. ([#302](https://github.com/opensearch-project/security-analytics/pull/302))
* Update others_web mappings. ([#304](https://github.com/opensearch-project/security-analytics/pull/304))
* Log message change for debugging. ([#321](https://github.com/opensearch-project/security-analytics/pull/321))

### Bug Fixes
* Service Returns Unhandled Error Response. ([#248](https://github.com/opensearch-project/security-analytics/pull/248))
* Correct linux mapping error. ([#263](https://github.com/opensearch-project/security-analytics/pull/263))
* GetIndexMapping API timestamp alias bugfix. ([#293](https://github.com/opensearch-project/security-analytics/pull/293))
* Query_field_names bugfix. ([#335](https://github.com/opensearch-project/security-analytics/pull/335))

### Maintenance
* Baselined MAINTAINERS and CODEOWNERS docs. ([#329](https://github.com/opensearch-project/security-analytics/pull/329))
* Bumped version to 2.6. ([#351](https://github.com/opensearch-project/security-analytics/pull/351))

### Documentation
* Added 2.6 release notes. ([#353](https://github.com/opensearch-project/security-analytics/pull/353))