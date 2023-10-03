/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.jobscheduler;

import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;

import java.util.Map;

public class DatasourceExtension implements JobSchedulerExtension {
    /**
     * Job index name for a datasource
     */
    public static final String JOB_INDEX_NAME = ".scheduler-security_analytics-threatintel-datasource"; //rename this...

    /**
     * Job index setting
     *
     * We want it to be single shard so that job can be run only in a single node by job scheduler.
     * We want it to expand to all replicas so that querying to this index can be done locally to reduce latency.
     */
    public static final Map<String, Object> INDEX_SETTING = Map.of("index.number_of_shards", 1, "index.number_of_replicas", "0-all", "index.hidden", true);

    @Override
    public String getJobType() {
        return "scheduler_security_analytics_threatintel_datasource";
    }

    @Override
    public String getJobIndex() {
        return JOB_INDEX_NAME;
    }

    @Override
    public ScheduledJobRunner getJobRunner() {
        return DatasourceRunner.getJobRunnerInstance();
    }

    @Override
    public ScheduledJobParser getJobParser() {
        return (parser, id, jobDocVersion) -> Datasource.PARSER.parse(parser, null);
    }
}
