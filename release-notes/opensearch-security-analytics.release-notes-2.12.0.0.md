## Version 2.12.0.0 2024-02-06

Compatible with OpenSearch 2.12.0

### Maintenance
* Increment to 2.12. ([#771](https://github.com/opensearch-project/security-analytics/pull/771))
* Onboard prod jenkins docker images to github actions ([#710](https://github.com/opensearch-project/security-analytics/pull/710))
* Match maintainer account username ([#438](https://github.com/opensearch-project/security-analytics/pull/438))
* Add to Codeowners ([#726](https://github.com/opensearch-project/security-analytics/pull/726))
* Fix codeowners to match maintainers ([#783](https://github.com/opensearch-project/security-analytics/pull/783))
* updated lucene MAX_DIMENSIONS path ([#607](https://github.com/opensearch-project/security-analytics/pull/607))
* Addresses changes related to default admin credentials ([#832](https://github.com/opensearch-project/security-analytics/pull/832))
* Upgrade Lucene Codec to Lucene99 + Upgrade to Gradle 8.5 ([#800](https://github.com/opensearch-project/security-analytics/pull/800))
* fix CVE-2023-2976 ([#835](https://github.com/opensearch-project/security-analytics/pull/835))

### Features
* Integrate threat intel feeds ([#669](https://github.com/opensearch-project/security-analytics/pull/669))

### Bug Fixes
* Fix for doc level query constructor change ([#651](https://github.com/opensearch-project/security-analytics/pull/651))
* Make threat intel async ([#703](https://github.com/opensearch-project/security-analytics/pull/703))
* Return empty response for empty mappings and no applied aliases ([#724](https://github.com/opensearch-project/security-analytics/pull/724))
* Fix threat intel plugin integ test ([#774](https://github.com/opensearch-project/security-analytics/pull/774))
* Use a common constant to specify the version for log type mappings ([#708](https://github.com/opensearch-project/security-analytics/pull/734))
* Sigma keywords field not handled correctly ([#725](https://github.com/opensearch-project/security-analytics/pull/725))
* Allow updation/deletion of custom log type if custom rule index is missing ([#767](https://github.com/opensearch-project/security-analytics/pull/767))
* Delete detector successfully if workflow is missing ([#790](https://github.com/opensearch-project/security-analytics/pull/790))
* fix null query filter conversion from sigma to query string query ([#722](https://github.com/opensearch-project/security-analytics/pull/722))
* add field based rules support in correlation engine ([#737](https://github.com/opensearch-project/security-analytics/pull/737))
* Reduce log level for informative message ([#203](https://github.com/opensearch-project/security-analytics/pull/203))

### Refactor
* Refactored alert tests ([#837](https://github.com/opensearch-project/security-analytics/pull/837))

### Documentation
* Added 2.12.0 release notes. ([#834](https://github.com/opensearch-project/security-analytics/pull/834))
* Add developer guide ([#791](https://github.com/opensearch-project/security-analytics/pull/791))