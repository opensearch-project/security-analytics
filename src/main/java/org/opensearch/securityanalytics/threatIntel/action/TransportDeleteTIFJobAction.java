/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.ingest.IngestService;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameterService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;

/**
 * Transport action to delete tif job
 */
public class TransportDeleteTIFJobAction extends HandledTransportAction<DeleteTIFJobRequest, AcknowledgedResponse> {
    private static final Logger log = LogManager.getLogger(TransportDeleteTIFJobAction.class);

    private static final long LOCK_DURATION_IN_SECONDS = 300l;
    private final TIFLockService lockService;
    private final IngestService ingestService;
    private final TIFJobParameterService tifJobParameterService;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final ThreadPool threadPool;

    /**
     * Constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param lockService the lock service
     * @param ingestService the ingest service
     * @param tifJobParameterService the tif job parameter service facade
     */
    @Inject
    public TransportDeleteTIFJobAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final TIFLockService lockService,
        final IngestService ingestService,
        final TIFJobParameterService tifJobParameterService,
        final ThreatIntelFeedDataService threatIntelFeedDataService,
        final ThreadPool threadPool
    ) {
        super(DeleteTIFJobAction.NAME, transportService, actionFilters, DeleteTIFJobRequest::new);
        this.lockService = lockService;
        this.ingestService = ingestService;
        this.tifJobParameterService = tifJobParameterService;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.threadPool = threadPool;
    }

    /**
     * We delete TIF job regardless of its state as long as we can acquire a lock
     *
     * @param task the task
     * @param request the request
     * @param listener the listener
     */
    @Override
    protected void doExecute(final Task task, final DeleteTIFJobRequest request, final ActionListener<AcknowledgedResponse> listener) {
        lockService.acquireLock(request.getName(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
            if (lock == null) {
                listener.onFailure(
                        new OpenSearchStatusException("Another processor is holding a lock on the resource. Try again later", RestStatus.BAD_REQUEST)
                );
                log.error("Another processor is holding lock, BAD_REQUEST exception", RestStatus.BAD_REQUEST);

                return;
            }
            try {
                // TODO: makes every sub-methods as async call to avoid using a thread in generic pool
                threadPool.generic().submit(() -> {
                    try {
                        deleteTIFJob(request.getName());
                        lockService.releaseLock(lock);
                        listener.onResponse(new AcknowledgedResponse(true));
                    } catch (Exception e) {
                        lockService.releaseLock(lock);
                        listener.onFailure(e);
                        log.error("delete tif job failed",e);
                    }
                });
            } catch (Exception e) {
                lockService.releaseLock(lock);
                listener.onFailure(e);
                log.error("Internal server error", e);
            }
        }, exception -> { listener.onFailure(exception); }));
    }

    protected void deleteTIFJob(final String tifJobName) throws IOException {
        TIFJobParameter tifJobParameter = tifJobParameterService.getJobParameter(tifJobName);
        if (tifJobParameter == null) {
            throw new ResourceNotFoundException("no such tifJobParameter exist");
        }
        TIFJobState previousState = tifJobParameter.getState();
        tifJobParameter.setState(TIFJobState.DELETING);
        tifJobParameterService.updateJobSchedulerParameter(tifJobParameter);

        try {
            threatIntelFeedDataService.deleteThreatIntelDataIndex(tifJobParameter.getIndices());
        } catch (Exception e) {
            if (previousState.equals(tifJobParameter.getState()) == false) {
                tifJobParameter.setState(previousState);
                tifJobParameterService.updateJobSchedulerParameter(tifJobParameter);
            }
            throw e;
        }
        tifJobParameterService.deleteTIFJobParameter(tifJobParameter);
    }
}
