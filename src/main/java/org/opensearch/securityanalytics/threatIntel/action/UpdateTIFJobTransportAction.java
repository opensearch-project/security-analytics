/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.common.TIFState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobTask;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobUpdateService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;

/**
 * Transport action to update tif job
 */
public class UpdateTIFJobTransportAction extends HandledTransportAction<UpdateTIFJobRequest, AcknowledgedResponse> {
    private static final long LOCK_DURATION_IN_SECONDS = 300l;
    private final TIFLockService lockService;
    private final TIFJobParameterService tifJobParameterService;
    private final TIFJobUpdateService tifJobUpdateService;
    private final ThreadPool threadPool;

    /**
     * Constructor
     *
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param lockService the lock service
     * @param tifJobParameterService the tif job parameter facade
     * @param tifJobUpdateService the tif job update service
     */
    @Inject
    public UpdateTIFJobTransportAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final TIFLockService lockService,
        final TIFJobParameterService tifJobParameterService,
        final TIFJobUpdateService tifJobUpdateService,
        final ThreadPool threadPool
    ) {
        super(UpdateTIFJobAction.NAME, transportService, actionFilters, UpdateTIFJobRequest::new);
        this.lockService = lockService;
        this.tifJobUpdateService = tifJobUpdateService;
        this.tifJobParameterService = tifJobParameterService;
        this.threadPool = threadPool;
    }

    /**
     * Get a lock and update tif job
     *
     * @param task the task
     * @param request the request
     * @param listener the listener
     */
    @Override
    protected void doExecute(final Task task, final UpdateTIFJobRequest request, final ActionListener<AcknowledgedResponse> listener) {
        lockService.acquireLock(request.getName(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
            if (lock == null) {
                listener.onFailure(
                        new OpenSearchStatusException("Another processor is holding a lock on the resource. Try again later", RestStatus.BAD_REQUEST)
                );
                return;
            }
            try {
                // TODO: makes every sub-methods as async call to avoid using a thread in generic pool
                threadPool.generic().submit(() -> {
                    try {
                        TIFJobParameter tifJobParameter = tifJobParameterService.getJobParameter(request.getName());
                        if (tifJobParameter == null) {
                            throw new ResourceNotFoundException("no such tifJobParameter exist");
                        }
                        if (TIFState.AVAILABLE.equals(tifJobParameter.getState()) == false) {
                            throw new IllegalArgumentException(
                                String.format(Locale.ROOT, "tif job is not in an [%s] state", TIFState.AVAILABLE)
                            );
                        }
                        updateIfChanged(request, tifJobParameter); //TODO: just want to update?
                        lockService.releaseLock(lock);
                        listener.onResponse(new AcknowledgedResponse(true));
                    } catch (Exception e) {
                        lockService.releaseLock(lock);
                        listener.onFailure(e);
                    }
                });
            } catch (Exception e) {
                lockService.releaseLock(lock);
                listener.onFailure(e);
            }
        }, exception -> listener.onFailure(exception)));
    }

    private void updateIfChanged(final UpdateTIFJobRequest request, final TIFJobParameter tifJobParameter) {
        boolean isChanged = false;
        if (isUpdateIntervalChanged(request)) {
            tifJobParameter.setSchedule(new IntervalSchedule(Instant.now(), (int) request.getUpdateInterval().getDays(), ChronoUnit.DAYS));
            tifJobParameter.setTask(TIFJobTask.ALL);
            isChanged = true;
        }

        if (isChanged) {
            tifJobParameterService.updateJobSchedulerParameter(tifJobParameter);
        }
    }

    /**
     * Update interval is changed as long as user provide one because
     * start time will get updated even if the update interval is same as current one.
     *
     * @param request the update tif job request
     * @return true if update interval is changed, and false otherwise
     */
    private boolean isUpdateIntervalChanged(final UpdateTIFJobRequest request) {
        return request.getUpdateInterval() != null;
    }
}
