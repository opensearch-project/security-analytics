/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.extensions.AcknowledgedResponse;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.ScheduledJobRunner;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.threadpool.ThreadPool;

import java.util.concurrent.atomic.AtomicReference;

/**
 * This is a background task which is responsible for updating threat intel feed iocs and the source config
 */
public class TIFSourceConfigRunner implements ScheduledJobRunner {
    private static final Logger log = LogManager.getLogger(TIFSourceConfigRunner.class);
    private static TIFSourceConfigRunner INSTANCE;
    public static TIFSourceConfigRunner getJobRunnerInstance() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (TIFSourceConfigRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new TIFSourceConfigRunner();
            return INSTANCE;
        }
    }

    private ClusterService clusterService;
    private TIFLockService lockService;
    private boolean initialized;
    private ThreadPool threadPool;
    private SATIFSourceConfigManagementService SaTifSourceConfigManagementService;
    private SATIFSourceConfigService SaTifSourceConfigService;

    private TIFSourceConfigRunner() {
        // Singleton class, use getJobRunner method instead of constructor
    }

    public void initialize(
            final ClusterService clusterService,
            final TIFLockService threatIntelLockService,
            final ThreadPool threadPool,
            final SATIFSourceConfigManagementService SaTifSourceConfigManagementService,
            final SATIFSourceConfigService SaTifSourceConfigService
    ) {
        this.clusterService = clusterService;
        this.lockService = threatIntelLockService;
        this.threadPool = threadPool;
        this.initialized = true;
        this.SaTifSourceConfigManagementService = SaTifSourceConfigManagementService;
        this.SaTifSourceConfigService = SaTifSourceConfigService;
    }

    @Override
    public void runJob(final ScheduledJobParameter jobParameter, final JobExecutionContext context) {
        if (initialized == false) {
            throw new AssertionError("This instance is not initialized");
        }

        if (jobParameter instanceof SATIFSourceConfig == false) {
            log.error("Illegal state exception: job parameter is not instance of TIF Source Config");
            throw new IllegalStateException(
                    "job parameter is not instance of TIF Source Config, type: " + jobParameter.getClass().getCanonicalName()
            );
        }

        if (this.clusterService == null) {
            throw new IllegalStateException("ClusterService is not initialized.");
        }

        if (this.threadPool == null) {
            throw new IllegalStateException("ThreadPool is not initialized.");
        }
        final LockService lockService = context.getLockService(); // todo
        threadPool.generic().submit(retrieveLockAndUpdateConfig((SATIFSourceConfig)jobParameter));
    }

    /**
     * Update threat intel feed config and data
     *
     * Lock is used so that only one of nodes run this task.
     *
     * @param SaTifSourceConfig the TIF source config that is scheduled onto the job scheduler
     */
    protected Runnable retrieveLockAndUpdateConfig(final SATIFSourceConfig SaTifSourceConfig) {
        log.info("Update job started for a TIF Source Config [{}]", SaTifSourceConfig.getId());

        return () -> lockService.acquireLock(
                SaTifSourceConfig.getName(),
                TIFLockService.LOCK_DURATION_IN_SECONDS,
                ActionListener.wrap(lock -> {
                    updateSourceConfigAndIOCs(SaTifSourceConfig, lockService.getRenewLockRunnable(new AtomicReference<>(lock)),
                            ActionListener.wrap(
                                    r -> lockService.releaseLock(lock),
                                    e -> {
                                        log.error("Failed to update threat intel source config " + SaTifSourceConfig.getName(), e);
                                        lockService.releaseLock(lock);
                                    }
                            ));
                }, e -> {
                    log.error("Failed to update. Another processor is holding a lock for job parameter[{}]", SaTifSourceConfig.getName());
                })
        );
    }

    protected void updateSourceConfigAndIOCs(final SATIFSourceConfig SaTifSourceConfig, final Runnable renewLock, ActionListener<AcknowledgedResponse> listener) {
        SaTifSourceConfigService.getTIFSourceConfig(SaTifSourceConfig.getId(), ActionListener.wrap(
                SaTifSourceConfigResponse -> {
                    if (SaTifSourceConfigResponse == null) {
                        log.info("Threat intel source config [{}] does not exist", SaTifSourceConfig.getName());
                        return;
                    }
                    if (TIFJobState.AVAILABLE.equals(SaTifSourceConfigResponse.getState()) == false) {
                        log.error("Invalid TIF job state. Expecting {} but received {}", TIFJobState.AVAILABLE, SaTifSourceConfigResponse.getState());
                        // update source config and log error
                        return;
                    }

                    // REFRESH FLOW
                    log.info("Refreshing IOCs and updating TIF source Config"); // place holder
                    SaTifSourceConfigManagementService.downloadAndSaveIOCs(SaTifSourceConfig, ActionListener.wrap(
                            // 1. call refresh IOC method (download and save IOCs)
                            // 1a. set state to refreshing
                            // 1b. delete old indices
                            // 1c. update or create iocs
                            r -> {
                                SaTifSourceConfig.setState(TIFJobState.AVAILABLE);
                                // 2. update source config as succeeded
                                SaTifSourceConfigManagementService.internalUpdateTIFSourceConfig(SaTifSourceConfig, ActionListener.wrap(
                                        updatedSaTifSourceConfigResponse -> {
                                            log.debug("Successfully refreshed IOCs for threat intel source config [{}]", SaTifSourceConfig.getId());
                                        }, e -> {
                                            log.error("Failed to update threat intel source config [{}]", SaTifSourceConfig.getId());
                                            listener.onFailure(e);
                                        }
                                ));
                            }, e -> {
                                // 3. update source config as failed
                                SaTifSourceConfig.setState(TIFJobState.REFRESH_FAILED);
                                SaTifSourceConfigManagementService.internalUpdateTIFSourceConfig(SaTifSourceConfig, ActionListener.wrap(
                                        updatedSaTifSourceConfigResponse -> {
                                            log.debug("Failed to refresh new IOCs for threat intel source config [{}]", SaTifSourceConfig.getId());
                                        }, ex -> {
                                            log.error("Failed to update threat intel source config [{}]", SaTifSourceConfig.getId());
                                            listener.onFailure(ex);
                                        }
                                ));
                                log.error("Failed to download and save IOCs for threat intel source config [{}]", SaTifSourceConfig.getId());
                                listener.onFailure(e);
                            }
                    ));
                }, e -> {
                    log.error("Failed to get threat intel source config [{}]", SaTifSourceConfig.getId());
                    listener.onFailure(e);
                }
        ));
    }
}