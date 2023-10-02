/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.jobscheduler;

import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
import org.opensearch.jobscheduler.spi.ScheduledJobParser;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;

public class DatasourceExtension implements JobSchedulerExtension {
    /**
     * Job index name for a datasource
     */
    public static final String JOB_INDEX_NAME = ".scheduler-securityanalytics-threatintel-datasource"; //todo check value

    @Override
    public String getJobType() {
        return "scheduler_securityanalytics_threatintel_datasource";
    } //todo check value

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
        return (parser, id, jobDocVersion) -> DatasourceParameter.PARSER.parse(parser, null);
    }
}
