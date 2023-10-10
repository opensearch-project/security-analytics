/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.time.Instant;

import org.opensearch.securityanalytics.threatIntel.common.TIFState;
import org.opensearch.securityanalytics.threatIntel.common.TIFExecutor;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;

/**
 * Job Parameter update task
 *
 * This is a background task which is responsible for updating threat intel feed data
 */
public class TIFJobRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);
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
    private TIFJobUpdateService jobSchedulerUpdateService;
    private TIFJobParameterService jobSchedulerParameterService;
    private TIFExecutor threatIntelExecutor;
    private TIFLockService lockService;
    private boolean initialized;

    private TIFJobRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public void initialize(
        final ClusterService clusterService,
        final TIFJobUpdateService jobSchedulerUpdateService,
        final TIFJobParameterService jobSchedulerParameterService,
        final TIFExecutor threatIntelExecutor,
        final TIFLockService threatIntelLockService
    ) {
        this.clusterService = clusterService;
        this.jobSchedulerUpdateService = jobSchedulerUpdateService;
        this.jobSchedulerParameterService = jobSchedulerParameterService;
        this.threatIntelExecutor = threatIntelExecutor;
        this.lockService = threatIntelLockService;
        this.initialized = true;
    }

    @Override
    public void runJob(final ScheduledJobParameter jobParameter, final JobExecutionContext context) {
        if (initialized == false) {
            throw new AssertionError("This instance is not initialized");
        }

        log.info("Update job started for a job parameter[{}]", jobParameter.getName());
        if (jobParameter instanceof TIFJobParameter == false) {
            log.error("Illegal state exception: job parameter is not instance of Job Scheduler Parameter");
            throw new IllegalStateException(
                    "job parameter is not instance of Job Scheduler Parameter, type: " + jobParameter.getClass().getCanonicalName()
            );
        }
        threatIntelExecutor.forJobSchedulerParameterUpdate().submit(updateJobRunner(jobParameter));
    }

    /**
     * Update threat intel feed data
     *
     * Lock is used so that only one of nodes run this task.
     *
     * @param jobParameter job parameter
     */
    protected Runnable updateJobRunner(final ScheduledJobParameter jobParameter) {
        return () -> {
            Optional<LockModel> lockModel = lockService.acquireLock(
                    jobParameter.getName(),
                    TIFLockService.LOCK_DURATION_IN_SECONDS
            );
            if (lockModel.isEmpty()) {
                log.error("Failed to update. Another processor is holding a lock for job parameter[{}]", jobParameter.getName());
                return;
            }

            LockModel lock = lockModel.get();
            try {
                updateJobParameter(jobParameter, lockService.getRenewLockRunnable(new AtomicReference<>(lock)));
            } catch (Exception e) {
                log.error("Failed to update job parameter[{}]", jobParameter.getName(), e);
            } finally {
                lockService.releaseLock(lock);
            }
        };
    }

    protected void updateJobParameter(final ScheduledJobParameter jobParameter, final Runnable renewLock) throws IOException {
        TIFJobParameter jobSchedulerParameter = jobSchedulerParameterService.getJobParameter(jobParameter.getName());
        /**
         * If delete request comes while update task is waiting on a queue for other update tasks to complete,
         * because update task for this jobSchedulerParameter didn't acquire a lock yet, delete request is processed.
         * When it is this jobSchedulerParameter's turn to run, it will find that the jobSchedulerParameter is deleted already.
         * Therefore, we stop the update process when data source does not exist.
         */
        if (jobSchedulerParameter == null) {
            log.info("Job parameter[{}] does not exist", jobParameter.getName());
            return;
        }

        if (TIFState.AVAILABLE.equals(jobSchedulerParameter.getState()) == false) {
            log.error("Invalid jobSchedulerParameter state. Expecting {} but received {}", TIFState.AVAILABLE, jobSchedulerParameter.getState());
            jobSchedulerParameter.disable();
            jobSchedulerParameter.getUpdateStats().setLastFailedAt(Instant.now());
            jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
            return;
        }
        try {
            jobSchedulerUpdateService.deleteUnusedIndices(jobSchedulerParameter);
            if (TIFJobTask.DELETE_UNUSED_INDICES.equals(jobSchedulerParameter.getTask()) == false) {
                jobSchedulerUpdateService.updateOrCreateThreatIntelFeedData(jobSchedulerParameter, renewLock);
            }
            jobSchedulerUpdateService.deleteUnusedIndices(jobSchedulerParameter);
        } catch (Exception e) {
            log.error("Failed to update jobSchedulerParameter for {}", jobSchedulerParameter.getName(), e);
            jobSchedulerParameter.getUpdateStats().setLastFailedAt(Instant.now());
            jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
        } finally {
            jobSchedulerUpdateService.updateJobSchedulerParameter(jobSchedulerParameter, jobSchedulerParameter.getSchedule(), TIFJobTask.ALL);
        }
    }

}