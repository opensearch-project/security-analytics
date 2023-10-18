///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//
//package org.opensearch.securityanalytics.threatIntel.jobscheduler;
//
//import org.opensearch.jobscheduler.spi.JobSchedulerExtension;
//import org.opensearch.jobscheduler.spi.ScheduledJobParser;
//import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
//
//import java.util.Map;
//
//public class TIFJobExtension implements JobSchedulerExtension {
//    /**
//     * Job index name for a TIF job
//     */
//    public static final String JOB_INDEX_NAME = ".scheduler-sap-threatintel-job";
//
//    /**
//     * Job index setting
//     *
//     * We want it to be single shard so that job can be run only in a single node by job scheduler.
//     * We want it to expand to all replicas so that querying to this index can be done locally to reduce latency.
//     */
//    public static final Map<String, Object> INDEX_SETTING = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all", "index.hidden", true);
//
//    @Override
//    public String getJobType() {
//        return "scheduler_sap_threatintel_job";
//    }
//
//    @Override
//    public String getJobIndex() {
//        return JOB_INDEX_NAME;
//    }
//
//    @Override
//    public ScheduledJobRunner getJobRunner() {
//        return TIFJobRunner.getJobRunnerInstance();
//    }
//
//    @Override
//    public ScheduledJobParser getJobParser() {
//        return (parser, id, jobDocVersion) -> TIFJobParameter.PARSER.parse(parser, null);
//    }
//}
