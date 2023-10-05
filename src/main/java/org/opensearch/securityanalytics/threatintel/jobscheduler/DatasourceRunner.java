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
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.time.Instant;

import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelExecutor;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelLockService;
import org.opensearch.securityanalytics.threatIntel.dao.DatasourceDao;
/**
 * Datasource update task
 *
 * This is a background task which is responsible for updating threat intel feed data
 */
public class DatasourceRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);
    private static DatasourceRunner INSTANCE;

    public static DatasourceRunner getJobRunnerInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (DatasourceRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new DatasourceRunner();
            return INSTANCE;
        }
    }

    private ClusterService clusterService;

    // threat intel specific variables
    private DatasourceUpdateService datasourceUpdateService;
    private DatasourceDao datasourceDao;
    private ThreatIntelExecutor threatIntelExecutor;
    private ThreatIntelLockService lockService;
    private boolean initialized;

    private DatasourceRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public void initialize(
        final ClusterService clusterService,
        final DatasourceUpdateService datasourceUpdateService,
        final DatasourceDao datasourceDao,
        final ThreatIntelExecutor threatIntelExecutor,
        final ThreatIntelLockService threatIntelLockService
    ) {
        this.clusterService = clusterService;
        this.datasourceUpdateService = datasourceUpdateService;
        this.datasourceDao = datasourceDao;
        this.threatIntelExecutor = threatIntelExecutor;
        this.lockService = threatIntelLockService;
        this.initialized = true;
    }

    @Override
    public void runJob(final ScheduledJobParameter jobParameter, final JobExecutionContext context) {
        if (initialized == false) {
            throw new AssertionError("this instance is not initialized");
        }

        log.info("Update job started for a datasource[{}]", jobParameter.getName());
        if (jobParameter instanceof Datasource == false) {
            log.error("Illegal state exception: job parameter is not instance of Datasource");
            throw new IllegalStateException(
                    "job parameter is not instance of Datasource, type: " + jobParameter.getClass().getCanonicalName()
            );
        }
        threatIntelExecutor.forDatasourceUpdate().submit(updateDatasourceRunner(jobParameter));
    }

    /**
     * Update threat intel feed data
     *
     * Lock is used so that only one of nodes run this task.
     *
     * @param jobParameter job parameter
     */
    protected Runnable updateDatasourceRunner(final ScheduledJobParameter jobParameter) {
        return () -> {
            Optional<LockModel> lockModel = lockService.acquireLock(
                    jobParameter.getName(),
                    ThreatIntelLockService.LOCK_DURATION_IN_SECONDS
            );
            if (lockModel.isEmpty()) {
                log.error("Failed to update. Another processor is holding a lock for datasource[{}]", jobParameter.getName());
                return;
            }

            LockModel lock = lockModel.get();
            try {
                updateDatasource(jobParameter, lockService.getRenewLockRunnable(new AtomicReference<>(lock)));
            } catch (Exception e) {
                log.error("Failed to update datasource[{}]", jobParameter.getName(), e);
            } finally {
                lockService.releaseLock(lock);
            }
        };
    }

    protected void updateDatasource(final ScheduledJobParameter jobParameter, final Runnable renewLock) throws IOException {
        Datasource datasource = datasourceDao.getDatasource(jobParameter.getName());
        /**
         * If delete request comes while update task is waiting on a queue for other update tasks to complete,
         * because update task for this datasource didn't acquire a lock yet, delete request is processed.
         * When it is this datasource's turn to run, it will find that the datasource is deleted already.
         * Therefore, we stop the update process when data source does not exist.
         */
        if (datasource == null) {
            log.info("Datasource[{}] does not exist", jobParameter.getName());
            return;
        }

        if (DatasourceState.AVAILABLE.equals(datasource.getState()) == false) {
            log.error("Invalid datasource state. Expecting {} but received {}", DatasourceState.AVAILABLE, datasource.getState());
            datasource.disable();
            datasource.getUpdateStats().setLastFailedAt(Instant.now());
            datasourceDao.updateDatasource(datasource);
            return;
        }
        try {
            datasourceUpdateService.deleteUnusedIndices(datasource);
            if (DatasourceTask.DELETE_UNUSED_INDICES.equals(datasource.getTask()) == false) {
                datasourceUpdateService.updateOrCreateThreatIntelFeedData(datasource, renewLock);
            }
            datasourceUpdateService.deleteUnusedIndices(datasource);
        } catch (Exception e) {
            log.error("Failed to update datasource for {}", datasource.getName(), e);
            datasource.getUpdateStats().setLastFailedAt(Instant.now());
            datasourceDao.updateDatasource(datasource);
        } finally { //post processing
            datasourceUpdateService.updateDatasource(datasource, datasource.getSchedule(), DatasourceTask.ALL);
        }
    }

}