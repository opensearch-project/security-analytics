/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.securityanalytics.action.GetMappingsViewAction;
import org.opensearch.securityanalytics.action.GetMappingsViewRequest;
import org.opensearch.securityanalytics.action.GetMappingsViewResponse;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetMappingsViewAction extends HandledTransportAction<GetMappingsViewRequest, GetMappingsViewResponse> {
    private MapperService mapperService;
    private ClusterService clusterService;
    private final ThreadPool threadPool;

    @Inject
    public TransportGetMappingsViewAction(
            TransportService transportService,
            ActionFilters actionFilters,
            GetMappingsViewAction getMappingsViewAction,
            MapperService mapperService,
            ClusterService clusterService,
            ThreadPool threadPool
    ) {
        super(getMappingsViewAction.NAME, transportService, actionFilters, GetMappingsViewRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, GetMappingsViewRequest request, ActionListener<GetMappingsViewResponse> actionListener) {
        this.threadPool.getThreadContext().stashContext();
        this.mapperService.getMappingsViewAction(request.getIndexName(), request.getRuleTopic(), actionListener);
    }
}