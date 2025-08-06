## Version 3.2.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.2.0

### Infrastructure
* Upgrade gradle to 8.14 and run CI with JDK 24 ([#1560](https://github.com/opensearch-project/security-analytics/pull/1560))
* Update the maven snapshot publish endpoint and credential ([#1544](https://github.com/opensearch-project/security-analytics/pull/1544))

### Maintenance
* [AUTO] Increment version to 3.2.0-SNAPSHOT ([#1552](https://github.com/opensearch-project/security-analytics/pull/1552))

### Refactoring
* Use instance of LockService instantiated in JobScheduler through Guice ([#1555](https://github.com/opensearch-project/security-analytics/pull/1555))