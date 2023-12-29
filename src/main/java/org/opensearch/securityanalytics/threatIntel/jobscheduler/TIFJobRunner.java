/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.time.Instant;

import org.opensearch.securityanalytics.threatIntel.DetectorThreatIntelService;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedIndexService;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.threadpool.ThreadPool;

/**
 * Job Parameter update task
 * This is a background task which is responsible for updating threat intel feed data
 */
public class TIFJobRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(TIFJobRunner.class);
    private static TIFJobRunner INSTANCE;
    public static TIFJobRunner getJobRunnerInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (TIFJobRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new TIFJobRunner();
            return INSTANCE;
        }
    }
    private ClusterService clusterService;

    // threat intel specific variables
    private ThreatIntelFeedIndexService threatIntelFeedIndexService;
    private TIFJobSchedulerMetadataService tifJobSchedulerMetadataService;
    private TIFLockService lockService;
    private boolean initialized;
    private ThreadPool threadPool;
    private DetectorThreatIntelService detectorThreatIntelService;

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    private TIFJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public void initialize(
        final ClusterService clusterService,
        final ThreatIntelFeedIndexService threatIntelFeedIndexService,
        final TIFJobSchedulerMetadataService tifJobSchedulerMetadataService,
        final TIFLockService threatIntelLockService,
        final ThreadPool threadPool,
        DetectorThreatIntelService detectorThreatIntelService
    ) {
        this.clusterService = clusterService;
        this.threatIntelFeedIndexService = threatIntelFeedIndexService;
        this.tifJobSchedulerMetadataService = tifJobSchedulerMetadataService;
        this.lockService = threatIntelLockService;
        this.threadPool = threadPool;
        this.initialized = true;
        this.detectorThreatIntelService = detectorThreatIntelService;
    }

    @Override
    public void runJob(final ScheduledJobParameter jobSchedulerMetadata, final JobExecutionContext context) {
        if (initialized == false) {
            throw new AssertionError("This instance is not initialized");
        }

        log.info("Update job started for a job parameter[{}]", jobSchedulerMetadata.getName());
        if (jobSchedulerMetadata instanceof TIFJobSchedulerMetadata == false) {
            log.error("Illegal state exception: job parameter is not instance of Job Scheduler Parameter");
            throw new IllegalStateException(
                    "job parameter is not instance of Job Scheduler Parameter, type: " + jobSchedulerMetadata.getClass().getCanonicalName()
            );
        }
        threadPool.generic().submit(updateJobRunner(jobSchedulerMetadata));
    }

    /**
     * Update threat intel feed data
     *
     * Lock is used so that only one of nodes run this task.
     *
     * @param jobSchedulerMetadata job scheduler metadata
     */
    protected Runnable updateJobRunner(final ScheduledJobParameter jobSchedulerMetadata) {
        return () -> {
            Optional<LockModel> lockModel = lockService.acquireLock(
                    jobSchedulerMetadata.getName(),
                    TIFLockService.LOCK_DURATION_IN_SECONDS
            );
            if (lockModel.isEmpty()) {
                log.error("Failed to update. Another processor is holding a lock for job parameter[{}]", jobSchedulerMetadata.getName());
                return;
            }

            LockModel lock = lockModel.get();
            try {
                updateThreatIntelFeed(jobSchedulerMetadata, lockService.getRenewLockRunnable(new AtomicReference<>(lock)));
            } catch (Exception e) {
                log.error("Failed to update job parameter[{}]", jobSchedulerMetadata.getName(), e);
            } finally {
                lockService.releaseLock(lock);
            }
        };
    }

    protected void updateThreatIntelFeed(final ScheduledJobParameter jobSchedulerMetadata, final Runnable renewLock) throws IOException {
        TIFJobSchedulerMetadata tifJobSchedulerMetadata = tifJobSchedulerMetadataService.getJobSchedulerMetadata(jobSchedulerMetadata.getName());
        /**
         * If delete request comes while update task is waiting on a queue for other update tasks to complete,
         * because update task for this tifJobSchedulerMetadata didn't acquire a lock yet, delete request is processed.
         * When it is this job scheduler's turn to run, it will find that the job scheduler metadata is deleted already.
         * Therefore, we stop the update process when data source does not exist.
         */
        if (tifJobSchedulerMetadata == null) {
            log.info("Job scheduler metadata[{}] does not exist", jobSchedulerMetadata.getName());
            return;
        }

        if (TIFJobState.AVAILABLE.equals(tifJobSchedulerMetadata.getState()) == false) {
            log.error("Invalid tifJobSchedulerMetadata state. Expecting {} but received {}", TIFJobState.AVAILABLE, tifJobSchedulerMetadata.getState());
            tifJobSchedulerMetadata.disable();
            tifJobSchedulerMetadata.getUpdateStats().setLastFailedAt(Instant.now());
            tifJobSchedulerMetadataService.updateJobSchedulerMetadata(tifJobSchedulerMetadata, null);
            return;
        }
        // create new TIF data and delete old ones
        List<String> oldIndices =  new ArrayList<>(tifJobSchedulerMetadata.getIndices()); //TODO
        threatIntelFeedIndexService.createThreatIntelFeed(tifJobSchedulerMetadata, renewLock, new ActionListener<>() {
            @Override
            public void onResponse(ThreatIntelIndicesResponse response) {
                if (response.isAcknowledged()) {
                    List<String> newFeedIndices = response.getIndices();
                    threatIntelFeedIndexService.deleteAllTifdIndices(oldIndices, newFeedIndices);
                    if (false == newFeedIndices.isEmpty()) {
                        detectorThreatIntelService.updateDetectorsWithLatestThreatIntelRules();
                    }
                } else {
                    log.error("Failed to update tifJobSchedulerMetadata for {}", tifJobSchedulerMetadata.getName());
                    tifJobSchedulerMetadata.getUpdateStats().setLastFailedAt(Instant.now());
                    tifJobSchedulerMetadataService.updateJobSchedulerMetadata(tifJobSchedulerMetadata, null);
                }
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Failed to update tifJobSchedulerMetadata for {}", tifJobSchedulerMetadata.getName(), e);
                tifJobSchedulerMetadata.getUpdateStats().setLastFailedAt(Instant.now());
                tifJobSchedulerMetadataService.updateJobSchedulerMetadata(tifJobSchedulerMetadata, null);
            }
        });
    }

}