/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetIndexMappingsAction extends HandledTransportAction<GetIndexMappingsRequest, GetIndexMappingsResponse> {
    private MapperService mapperService;
    private ClusterService clusterService;

    private final ThreadPool threadPool;

    @Inject
    public TransportGetIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            GetIndexMappingsAction getIndexMappingsAction,
            MapperService mapperService,
            ClusterService clusterService,
            ThreadPool threadPool
    ) {
        super(getIndexMappingsAction.NAME, transportService, actionFilters, GetIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, GetIndexMappingsRequest request, ActionListener<GetIndexMappingsResponse> actionListener) {
        this.threadPool.getThreadContext().stashContext();
        IndexMetadata index = clusterService.state().metadata().index(request.getIndexName());
        if (index == null) {
            actionListener.onFailure(new IllegalStateException("Could not find index [" + request.getIndexName() + "]"));
            return;
        }
        mapperService.getMappingAction(request.getIndexName(), actionListener);
    }
}