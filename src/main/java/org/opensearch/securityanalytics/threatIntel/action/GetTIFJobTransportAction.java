/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.OpenSearchException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.Collections;
import java.util.List;

/**
 * Transport action to get tif job
 */
public class GetTIFJobTransportAction extends HandledTransportAction<GetTIFJobRequest, GetTIFJobResponse> {
    private final TIFJobParameterService tifJobParameterService;

    /**
     * Default constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param tifJobParameterService the tif job parameter service facade
     */
    @Inject
    public GetTIFJobTransportAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final TIFJobParameterService tifJobParameterService
    ) {
        super(GetTIFJobAction.NAME, transportService, actionFilters, GetTIFJobRequest::new);
        this.tifJobParameterService = tifJobParameterService;
    }

    @Override
    protected void doExecute(final Task task, final GetTIFJobRequest request, final ActionListener<GetTIFJobResponse> listener) {
        if (shouldGetAllTIFJobs(request)) {
            // We don't expect too many tif jobs. Therefore, querying all tif jobs without pagination should be fine.
            tifJobParameterService.getAllTIFJobParameters(newActionListener(listener));
        } else {
            tifJobParameterService.getTIFJobParameters(request.getNames(), newActionListener(listener));
        }
    }

    private boolean shouldGetAllTIFJobs(final GetTIFJobRequest request) {
        if (request.getNames() == null) {
            throw new OpenSearchException("names in a request should not be null");
        }
        return request.getNames().length == 0 || (request.getNames().length == 1 && "_all".equals(request.getNames()[0]));
    }

    protected ActionListener<List<TIFJobParameter>> newActionListener(final ActionListener<GetTIFJobResponse> listener) {
        return new ActionListener<>() {
            @Override
            public void onResponse(final List<TIFJobParameter> tifJobParameters) {
                listener.onResponse(new GetTIFJobResponse(tifJobParameters));
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof IndexNotFoundException) {
                    listener.onResponse(new GetTIFJobResponse(Collections.emptyList()));
                    return;
                }
                listener.onFailure(e);
            }
        };
    }
}
