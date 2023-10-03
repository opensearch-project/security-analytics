/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.OpenSearchException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.securityanalytics.threatintel.dao.DatasourceDao;
import org.opensearch.securityanalytics.threatintel.jobscheduler.Datasource;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.Collections;
import java.util.List;

/**
 * Transport action to get datasource
 */
public class GetDatasourceTransportAction extends HandledTransportAction<GetDatasourceRequest, GetDatasourceResponse> {
    private final DatasourceDao datasourceDao;

    /**
     * Default constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param datasourceDao the datasource facade
     */
    @Inject
    public GetDatasourceTransportAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final DatasourceDao datasourceDao
    ) {
        super(GetDatasourceAction.NAME, transportService, actionFilters, GetDatasourceRequest::new);
        this.datasourceDao = datasourceDao;
    }

    @Override
    protected void doExecute(final Task task, final GetDatasourceRequest request, final ActionListener<GetDatasourceResponse> listener) {
        if (shouldGetAllDatasource(request)) {
            // We don't expect too many data sources. Therefore, querying all data sources without pagination should be fine.
            datasourceDao.getAllDatasources(newActionListener(listener));
        } else {
            datasourceDao.getDatasources(request.getNames(), newActionListener(listener));
        }
    }

    private boolean shouldGetAllDatasource(final GetDatasourceRequest request) {
        if (request.getNames() == null) {
            throw new OpenSearchException("names in a request should not be null");
        }

        return request.getNames().length == 0 || (request.getNames().length == 1 && "_all".equals(request.getNames()[0]));
    }

    protected ActionListener<List<Datasource>> newActionListener(final ActionListener<GetDatasourceResponse> listener) {
        return new ActionListener<>() {
            @Override
            public void onResponse(final List<Datasource> datasources) {
                listener.onResponse(new GetDatasourceResponse(datasources));
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof IndexNotFoundException) {
                    listener.onResponse(new GetDatasourceResponse(Collections.emptyList()));
                    return;
                }
                listener.onFailure(e);
            }
        };
    }
}
