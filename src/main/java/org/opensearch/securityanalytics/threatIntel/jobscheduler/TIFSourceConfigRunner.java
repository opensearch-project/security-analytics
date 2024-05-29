///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//
//package org.opensearch.securityanalytics.threatIntel.jobscheduler;
//
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//import org.opensearch.cluster.service.ClusterService;
//import org.opensearch.core.action.ActionListener;
//import org.opensearch.jobscheduler.spi.JobExecutionContext;
//import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
//import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
//import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
//import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
//import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
//import org.opensearch.securityanalytics.threatIntel.dao.SATIFSourceConfigDao;
//import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
//import org.opensearch.threadpool.ThreadPool;
//
//import java.time.Instant;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.concurrent.atomic.AtomicReference;
//
///**
// *
// * This is a background task which is responsible for updating threat intel feed data and the config
// */
//public class TIFSourceConfigRunner implements ScheduledJobRunner {
//    private static final Logger log = LogManager.getLogger(TIFSourceConfigRunner.class);
//    private static TIFSourceConfigRunner INSTANCE;
//
//    public static TIFSourceConfigRunner getJobRunnerInstance() {
//        if (INSTANCE != null) {
//            return INSTANCE;
//        }
//        synchronized (TIFSourceConfigRunner.class) {
//            if (INSTANCE != null) {
//                return INSTANCE;
//            }
//            INSTANCE = new TIFSourceConfigRunner();
//            return INSTANCE;
//        }
//    }
//
//    private ClusterService clusterService;
//
//    // threat intel specific variables
//    private TIFLockService lockService;
//    private boolean initialized;
//    private ThreadPool threadPool;
//
//    public void setThreadPool(ThreadPool threadPool) {
//        this.threadPool = threadPool;
//    }
//
//    private TIFSourceConfigRunner() {
//        // Singleton class, use getJobRunner method instead of constructor
//    }
//
//    public void initialize(
//            final ClusterService clusterService,
//            final TIFLockService threatIntelLockService,
//            final ThreadPool threadPool
//    ) {
//        this.clusterService = clusterService;
//        this.lockService = threatIntelLockService;
//        this.threadPool = threadPool;
//        this.initialized = true;
//    }
//
//    @Override
//    public void runJob(final ScheduledJobParameter jobParameter, final JobExecutionContext context) {
//        if (initialized == false) {
//            throw new AssertionError("This instance is not initialized");
//        }
//
//        log.info("Update job started for a job parameter[{}]", jobParameter.getName());
//        if (jobParameter instanceof SATIFSourceConfig == false) {
//            log.error("Illegal state exception: job parameter is not instance of TIF Source Config");
//            throw new IllegalStateException(
//                    "job parameter is not instance of TIF Source Config, type: " + jobParameter.getClass().getCanonicalName()
//            );
//        }
//        threadPool.generic().submit(updateJobRunner(jobParameter));
//    }
//
//
//    /**
//     * Update threat intel feed config and data
//     *
//     * Lock is used so that only one of nodes run this task.
//     *
//     * @param jobParameter job parameter
//     */
//    protected Runnable updateJobRunner(final ScheduledJobParameter jobParameter) {
//        return () -> lockService.acquireLock(
//                jobParameter.getName(),
//                TIFLockService.LOCK_DURATION_IN_SECONDS,
//                ActionListener.wrap(lock -> {
//                    updateJobParameter(jobParameter, lockService.getRenewLockRunnable(new AtomicReference<>(lock)),
//                            ActionListener.wrap(
//                                    r -> lockService.releaseLock(lock),
//                                    e -> {
//                                        log.error("Failed to update job parameter " + jobParameter.getName(), e);
//                                        lockService.releaseLock(lock);
//                                    }
//                            ));
//                }, e -> {
//                    log.error("Failed to update. Another processor is holding a lock for job parameter[{}]", jobParameter.getName());
//                })
//        );
//    }
//
//    protected void updateJobParameter(final ScheduledJobParameter jobParameter, final Runnable renewLock, ActionListener<Void> listener) {
//
//        jobSchedulerParameterService.getJobParameter(jobParameter.getName(), ActionListener.wrap(
//                jobSchedulerParameter -> {
//                    /**
//                     * If delete request comes while update task is waiting on a queue for other update tasks to complete,
//                     * because update task for this jobSchedulerParameter didn't acquire a lock yet, delete request is processed.
//                     * When it is this jobSchedulerParameter's turn to run, it will find that the jobSchedulerParameter is deleted already.
//                     * Therefore, we stop the update process when data source does not exist.
//                     */
//                    if (jobSchedulerParameter == null) {
//                        log.info("Job parameter[{}] does not exist", jobParameter.getName());
//                        return;
//                    }
//
//                    if (TIFJobState.AVAILABLE.equals(jobSchedulerParameter.getState()) == false) {
//                        log.error("Invalid jobSchedulerParameter state. Expecting {} but received {}", TIFJobState.AVAILABLE, jobSchedulerParameter.getState());
//                        jobSchedulerParameter.disable();
//                        jobSchedulerParameter.getUpdateStats().setLastFailedAt(Instant.now());
//                        jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter, ActionListener.wrap(
//                                r-> {}, e -> log.error("Failed to update job scheduler parameter in Threat intel feed update job")
//                        ));
//                    }
//
//                    // create new TIF data and delete old ones
//                    List<String> oldIndices =  new ArrayList<>(jobSchedulerParameter.getIndices());
//                    jobSchedulerUpdateService.createThreatIntelFeedData(jobSchedulerParameter, renewLock, new ActionListener<>() {
//                        @Override
//                        public void onResponse(ThreatIntelIndicesResponse response) {
//                            if (response.isAcknowledged()) {
//                                List<String> newFeedIndices = response.getIndices();
//                                jobSchedulerUpdateService.deleteAllTifdIndices(oldIndices, newFeedIndices);
//                                if (false == newFeedIndices.isEmpty()) {
//                                    detectorThreatIntelService.updateDetectorsWithLatestThreatIntelRules();
//                                }
//                            } else {
//                                log.error("Failed to update jobSchedulerParameter for {}", jobSchedulerParameter.getName());
//                                jobSchedulerParameter.getUpdateStats().setLastFailedAt(Instant.now());
//                                jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter, ActionListener.wrap(
//                                        r-> {}, e -> log.error("Failed to update job scheduler parameter in Threat intel feed update job")
//                                ));
//                            }
//                        }
//
//                        @Override
//                        public void onFailure(Exception e) {
//                            log.error("Failed to update jobSchedulerParameter for {}", jobSchedulerParameter.getName(), e);
//                            jobSchedulerParameter.getUpdateStats().setLastFailedAt(Instant.now());
//                            jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter, ActionListener.wrap(
//                                    r-> {}, ex -> log.error("Failed to update job scheduler parameter in Threat intel feed update job")
//                            ));
//                        }
//                    });
//                    listener.onResponse(null);
//                },
//                e -> {
//                    listener.onFailure(e);
//                }
//        ));
//    }
//
//}