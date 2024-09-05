## Version 2.17.0.0 2024-09-05

Compatible with OpenSearch 2.17.0

### Maintenance
* update build.gradle to use alerting-spi snapshot version ([#1217](https://github.com/opensearch-project/security-analytics/pull/1217))

### Enhancement
* added triggers in getDetectors API response ([#1226](https://github.com/opensearch-project/security-analytics/pull/1226))
* secure rest tests for threat intel monitor apis ([#1212](https://github.com/opensearch-project/security-analytics/pull/1212))

### Bug Fixes
* Adds user validation for threat intel transport layer classes and stashes the thread context for all system index interactions ([#1207](https://github.com/opensearch-project/security-analytics/pull/1207))
* fix mappings integ tests ([#1213](https://github.com/opensearch-project/security-analytics/pull/1213))
* Bug fixes for threat intel ([#1223](https://github.com/opensearch-project/security-analytics/pull/1223))
* make threat intel run with standard detectors ([#1234](https://github.com/opensearch-project/security-analytics/pull/1234))
* Fixed searchString bug. Removed nested IOC mapping structure. ([#1239](https://github.com/opensearch-project/security-analytics/pull/1239))
* adds toggling refresh disable/enable for deactivate/activate operation while updating URL_DOWNLOAD type configs ([#1240](https://github.com/opensearch-project/security-analytics/pull/1240))
* Make threat intel source config release lock event driven ([#1254](https://github.com/opensearch-project/security-analytics/pull/1254))
* Fix S3 validation errors not caught by action listener ([#1257](https://github.com/opensearch-project/security-analytics/pull/1257))
* Clean up empty IOC indices created by failed source configs ([#1267](https://github.com/opensearch-project/security-analytics/pull/1267))
* Fix threat intel multinode tests ([#1274](https://github.com/opensearch-project/security-analytics/pull/1274))
* Update threat intel job mapping to new version ([#1272](https://github.com/opensearch-project/security-analytics/pull/1272))
* Stash context for List IOCs Api ([#1278](https://github.com/opensearch-project/security-analytics/pull/1278))

### Documentation
* Added 2.17.0 release notes. ([#1290](https://github.com/opensearch-project/security-analytics/pull/1290))