/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import static org.opensearch.securityanalytics.threatIntel.common.ThreatIntelLockService.LOCK_DURATION_IN_SECONDS;

import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.StepListener;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelLockService;
import org.opensearch.securityanalytics.threatIntel.dao.DatasourceDao;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceUpdateService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

/**
 * Transport action to create datasource
 */
public class PutDatasourceTransportAction extends HandledTransportAction<PutDatasourceRequest, AcknowledgedResponse> {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private final ThreadPool threadPool;
    private final DatasourceDao datasourceDao;
    private final DatasourceUpdateService datasourceUpdateService;
    private final ThreatIntelLockService lockService;

    /**
     * Default constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param threadPool the thread pool
     * @param datasourceDao the datasource facade
     * @param datasourceUpdateService the datasource update service
     * @param lockService the lock service
     */
    @Inject
    public PutDatasourceTransportAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final DatasourceDao datasourceDao,
            final DatasourceUpdateService datasourceUpdateService,
            final ThreatIntelLockService lockService
    ) {
        super(PutDatasourceAction.NAME, transportService, actionFilters, PutDatasourceRequest::new);
        this.threadPool = threadPool;
        this.datasourceDao = datasourceDao;
        this.datasourceUpdateService = datasourceUpdateService;
        this.lockService = lockService;
    }

    @Override
    protected void doExecute(final Task task, final PutDatasourceRequest request, final ActionListener<AcknowledgedResponse> listener) {
        lockService.acquireLock(request.getName(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
            if (lock == null) {
                listener.onFailure(
                        new ConcurrentModificationException("another processor is holding a lock on the resource. Try again later")
                );
                log.error("another processor is a lock, BAD_REQUEST error", RestStatus.BAD_REQUEST);
                return;
            }
            try {
                internalDoExecute(request, lock, listener);
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
            final PutDatasourceRequest request,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        StepListener<Void> createIndexStep = new StepListener<>();
        datasourceDao.createIndexIfNotExists(createIndexStep);
        createIndexStep.whenComplete(v -> {
            Datasource datasource = Datasource.Builder.build(request);
            datasourceDao.putDatasource(datasource, getIndexResponseListener(datasource, lock, listener));
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
    protected ActionListener<IndexResponse> getIndexResponseListener(
            final Datasource datasource,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        return new ActionListener<>() {
            @Override
            public void onResponse(final IndexResponse indexResponse) {
                // This is user initiated request. Therefore, we want to handle the first datasource update task in a generic thread
                // pool.
                threadPool.generic().submit(() -> {
                    AtomicReference<LockModel> lockReference = new AtomicReference<>(lock);
                    try {
                        createDatasource(datasource, lockService.getRenewLockRunnable(lockReference));
                    } finally {
                        lockService.releaseLock(lockReference.get());
                    }
                });
                listener.onResponse(new AcknowledgedResponse(true));
            }

            @Override
            public void onFailure(final Exception e) {
                lockService.releaseLock(lock);
                if (e instanceof VersionConflictEngineException) {
                    log.error("datasource already exists");
                    listener.onFailure(new ResourceAlreadyExistsException("datasource [{}] already exists", datasource.getName()));
                } else {
                    log.error("Internal server error");
                    listener.onFailure(e);
                }
            }
        };
    }

    protected void createDatasource(final Datasource datasource, final Runnable renewLock) {
        if (DatasourceState.CREATING.equals(datasource.getState()) == false) {
            log.error("Invalid datasource state. Expecting {} but received {}", DatasourceState.CREATING, datasource.getState());
            markDatasourceAsCreateFailed(datasource);
            return;
        }

        try {
            datasourceUpdateService.updateOrCreateThreatIntelFeedData(datasource, renewLock);
        } catch (Exception e) {
            log.error("Failed to create datasource for {}", datasource.getName(), e);
            markDatasourceAsCreateFailed(datasource);
        }
    }

    private void markDatasourceAsCreateFailed(final Datasource datasource) {
        datasource.getUpdateStats().setLastFailedAt(Instant.now());
        datasource.setState(DatasourceState.CREATE_FAILED);
        try {
            datasourceDao.updateDatasource(datasource);
        } catch (Exception e) {
            log.error("Failed to mark datasource state as CREATE_FAILED for {}", datasource.getName(), e);
        }
    }
}

