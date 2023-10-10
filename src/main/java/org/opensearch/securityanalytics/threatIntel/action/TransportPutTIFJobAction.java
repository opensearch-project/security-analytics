/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

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
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobUpdateService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.util.ConcurrentModificationException;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.LOCK_DURATION_IN_SECONDS;

/**
 * Transport action to create tif job
 */
public class TransportPutTIFJobAction extends HandledTransportAction<PutTIFJobRequest, AcknowledgedResponse> {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private final ThreadPool threadPool;
    private final TIFJobParameterService tifJobParameterService;
    private final TIFJobUpdateService tifJobUpdateService;
    private final TIFLockService lockService;

    /**
     * Default constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param threadPool the thread pool
     * @param tifJobParameterService the tif job parameter service facade
     * @param tifJobUpdateService the tif job update service
     * @param lockService the lock service
     */
    @Inject
    public TransportPutTIFJobAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final TIFJobParameterService tifJobParameterService,
            final TIFJobUpdateService tifJobUpdateService,
            final TIFLockService lockService
    ) {
        super(PutTIFJobAction.NAME, transportService, actionFilters, PutTIFJobRequest::new);
        this.threadPool = threadPool;
        this.tifJobParameterService = tifJobParameterService;
        this.tifJobUpdateService = tifJobUpdateService;
        this.lockService = lockService;
    }

    @Override
    protected void doExecute(final Task task, final PutTIFJobRequest request, final ActionListener<AcknowledgedResponse> listener) {
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
            final PutTIFJobRequest request,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        StepListener<Void> createIndexStep = new StepListener<>();
        tifJobParameterService.createIndexIfNotExists(createIndexStep);
        createIndexStep.whenComplete(v -> {
            TIFJobParameter tifJobParameter = TIFJobParameter.Builder.build(request);
            tifJobParameterService.putTIFJobParameter(tifJobParameter, getIndexResponseListener(tifJobParameter, lock, listener));
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
            final TIFJobParameter tifJobParameter,
            final LockModel lock,
            final ActionListener<AcknowledgedResponse> listener
    ) {
        return new ActionListener<>() {
            @Override
            public void onResponse(final IndexResponse indexResponse) {
                // This is user initiated request. Therefore, we want to handle the first tifJobParameter update task in a generic thread
                // pool.
                threadPool.generic().submit(() -> {
                    AtomicReference<LockModel> lockReference = new AtomicReference<>(lock);
                    try {
                        createTIFJob(tifJobParameter, lockService.getRenewLockRunnable(lockReference));
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
                    log.error("tifJobParameter already exists");
                    listener.onFailure(new ResourceAlreadyExistsException("tifJobParameter [{}] already exists", tifJobParameter.getName()));
                } else {
                    log.error("Internal server error");
                    listener.onFailure(e);
                }
            }
        };
    }

    protected void createTIFJob(final TIFJobParameter tifJobParameter, final Runnable renewLock) {
        if (TIFJobState.CREATING.equals(tifJobParameter.getState()) == false) {
            log.error("Invalid tifJobParameter state. Expecting {} but received {}", TIFJobState.CREATING, tifJobParameter.getState());
            markTIFJobAsCreateFailed(tifJobParameter);
            return;
        }

        try {
            tifJobUpdateService.createThreatIntelFeedData(tifJobParameter, renewLock);
        } catch (Exception e) {
            log.error("Failed to create tifJobParameter for {}", tifJobParameter.getName(), e);
            markTIFJobAsCreateFailed(tifJobParameter);
        }
    }

    private void markTIFJobAsCreateFailed(final TIFJobParameter tifJobParameter) {
        tifJobParameter.getUpdateStats().setLastFailedAt(Instant.now());
        tifJobParameter.setState(TIFJobState.CREATE_FAILED);
        try {
            tifJobParameterService.updateJobSchedulerParameter(tifJobParameter);
        } catch (Exception e) {
            log.error("Failed to mark tifJobParameter state as CREATE_FAILED for {}", tifJobParameter.getName(), e);
        }
    }
}

