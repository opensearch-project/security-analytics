/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.StepListener;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadata;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadataService;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedIndexService;
import org.opensearch.securityanalytics.util.IndexUtils;

import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.LOCK_DURATION_IN_SECONDS;
import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadata.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

/**
 * Service class to fetch threat intel feed data and save IoCs and to create the threat intel feeds job
 */
public class ThreatIntelHighLevelHandler {
    private static final Logger log = LogManager.getLogger(ThreatIntelHighLevelHandler.class);
    private final TIFJobSchedulerMetadataService tifJobSchedulerMetadataService;
    private final ThreatIntelFeedIndexService threatIntelFeedIndexService;
    private final TIFLockService lockService;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;


    /**
     * Default constructor
     * @param tifJobSchedulerMetadata the tif job parameter service facade
     * @param threatIntelFeedIndexService the tif index service facade
     * @param threatIntelFeedDataService the threat intel feed data service facade
     * @param lockService the lock service
     * @param clusterService
     * @param indexNameExpressionResolver
     */
    @Inject
    public ThreatIntelHighLevelHandler(
            final TIFJobSchedulerMetadataService tifJobSchedulerMetadata,
            final ThreatIntelFeedIndexService threatIntelFeedIndexService,
            final ThreatIntelFeedDataService threatIntelFeedDataService,
            final TIFLockService lockService,
            ClusterService clusterService,
            IndexNameExpressionResolver indexNameExpressionResolver
    ) {
        this.tifJobSchedulerMetadataService = tifJobSchedulerMetadata;
        this.threatIntelFeedIndexService = threatIntelFeedIndexService;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.lockService = lockService;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    public void getThreatIntelFeedData(
            ActionListener<List<ThreatIntelFeedData>> listener
    ) throws InterruptedException {
        // check if threat intel feed index exists
        String tifdIndex = getLatestIndexByCreationDate();

        // if it doesn't exist, then create the data feed and the job scheduler job
        if (tifdIndex == null) {
            CountDownLatch countDownLatch = new CountDownLatch(1);
            doExecute(new ActionListener<>() {
                @Override
                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                    log.debug("Acknowledged threat intel feed updater job created");
                    countDownLatch.countDown();
                    String tifdIndex = getLatestIndexByCreationDate();
                    threatIntelFeedDataService.getThreatIntelFeedData(listener, tifdIndex);
                }
                @Override
                public void onFailure(Exception e) {
                    log.debug("Failed to create threat intel feed updater job", e);
                    countDownLatch.countDown();
                }
            });
            countDownLatch.await();

            // if index exists, then directly get the threat intel data
        } else {
            threatIntelFeedDataService.getThreatIntelFeedData(listener, tifdIndex);
        }
    }

    protected void doExecute(final ActionListener<AcknowledgedResponse> listener) {
        lockService.acquireLock("feed_updater", LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
            if (lock == null) {
                listener.onFailure(
                        new ConcurrentModificationException("another processor is holding a lock on the resource. Try again later")
                );
                log.error("another processor is a lock, BAD_REQUEST error", RestStatus.BAD_REQUEST);
                return;
            }
            try {
                internalDoExecute(lock, listener);
            } catch (Exception e) {
                lockService.releaseLock(lock);
                listener.onFailure(e);
                log.error("listener failed when executing", e);
            }
        }, exception -> {
            listener.onFailure(exception);
            log.error("execution failed", exception);
        }));
    }

    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
    protected void internalDoExecute(
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        TimeValue updateInterval = clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL);
        StepListener<Void> createIndexStep = new StepListener<>();
        tifJobSchedulerMetadataService.createJobIndexIfNotExists(createIndexStep);
        createIndexStep.whenComplete(v -> {
            TIFJobSchedulerMetadata tifJobSchedulerMetadata = TIFJobSchedulerMetadata.Builder.build("feed_updater", updateInterval);
            tifJobSchedulerMetadataService.saveTIFJobSchedulerMetadata(tifJobSchedulerMetadata, createThreatIntelFeedIndex(tifJobSchedulerMetadata, lock, listener));
        }, exception -> {
            lockService.releaseLock(lock);
            log.error("failed to release lock", exception);
            listener.onFailure(exception);
        });
    }

    /**
     * This method takes lock as a parameter and is responsible for releasing lock
     * unless exception is thrown
     */
    protected ActionListener<IndexResponse> createThreatIntelFeedIndex(
            final TIFJobSchedulerMetadata tifJobSchedulerMetadata,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        return new ActionListener<>() {
            @Override
            public void onResponse(final IndexResponse indexResponse) {
                AtomicReference<LockModel> lockReference = new AtomicReference<>(lock);
                createThreatIntelFeedIndex(tifJobSchedulerMetadata, lockService.getRenewLockRunnable(lockReference), new ActionListener<>() {
                    @Override
                    public void onResponse(ThreatIntelIndicesResponse threatIntelIndicesResponse) {
                        if (threatIntelIndicesResponse.isAcknowledged()) {
                            lockService.releaseLock(lockReference.get());
                            listener.onResponse(new AcknowledgedResponse(true));
                        } else {
                            onFailure(new OpenSearchStatusException("creation of threat intel feed data failed", RestStatus.INTERNAL_SERVER_ERROR));
                        }
                    }
                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
            }

            @Override
            public void onFailure(final Exception e) {
                lockService.releaseLock(lock);
                if (e instanceof VersionConflictEngineException) {
                    log.error("tifJobSchedulerMetadata already exists");
                    listener.onFailure(new ResourceAlreadyExistsException("tifJobSchedulerMetadata [{}] already exists", tifJobSchedulerMetadata.getName()));
                } else {
                    log.error("Internal server error");
                    listener.onFailure(e);
                }
            }
        };
    }

    protected void createThreatIntelFeedIndex(final TIFJobSchedulerMetadata tifJobSchedulerMetadata, final Runnable renewLock, final ActionListener<ThreatIntelIndicesResponse> listener) {
        if (TIFJobState.CREATING.equals(tifJobSchedulerMetadata.getState()) == false) {
            log.error("Invalid tifJobSchedulerMetadata state. Expecting {} but received {}", TIFJobState.CREATING, tifJobSchedulerMetadata.getState());
            markTIFJobAsCreateFailed(tifJobSchedulerMetadata, listener);
            return;
        }

        try {
            threatIntelFeedIndexService.createThreatIntelFeed(tifJobSchedulerMetadata, renewLock, listener);
        } catch (Exception e) {
            log.error("Failed to create tifJobSchedulerMetadata for {}", tifJobSchedulerMetadata.getName(), e);
            markTIFJobAsCreateFailed(tifJobSchedulerMetadata, listener);
        }
    }

    private void markTIFJobAsCreateFailed(final TIFJobSchedulerMetadata tifJobSchedulerMetadata, final ActionListener<ThreatIntelIndicesResponse> listener) {
        tifJobSchedulerMetadata.getUpdateStats().setLastFailedAt(Instant.now());
        tifJobSchedulerMetadata.setState(TIFJobState.CREATE_FAILED);
        try {
            tifJobSchedulerMetadataService.updateJobSchedulerMetadata(tifJobSchedulerMetadata, listener);
        } catch (Exception e) {
            log.error("Failed to mark tifJobSchedulerMetadata state as CREATE_FAILED for {}", tifJobSchedulerMetadata.getName(), e);
        }
    }

    private String getLatestIndexByCreationDate() {
        return IndexUtils.getNewIndexByCreationDate(
                this.clusterService.state(),
                this.indexNameExpressionResolver,
                THREAT_INTEL_DATA_INDEX_NAME_PREFIX + "*"
        );
    }
}

