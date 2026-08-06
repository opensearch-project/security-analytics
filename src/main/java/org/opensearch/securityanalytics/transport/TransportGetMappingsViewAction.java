/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.client.Client;
import org.opensearch.securityanalytics.action.GetMappingsViewAction;
import org.opensearch.securityanalytics.action.GetMappingsViewRequest;
import org.opensearch.securityanalytics.action.GetMappingsViewResponse;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetMappingsViewAction extends HandledTransportAction<GetMappingsViewRequest, GetMappingsViewResponse> {
    private MapperService mapperService;
    private ClusterService clusterService;
    private final ThreadPool threadPool;
    private final Client client;

    @Inject
    public TransportGetMappingsViewAction(
            TransportService transportService,
            ActionFilters actionFilters,
            GetMappingsViewAction getMappingsViewAction,
            MapperService mapperService,
            ClusterService clusterService,
            ThreadPool threadPool,
            Client client
    ) {
        super(getMappingsViewAction.NAME, transportService, actionFilters, GetMappingsViewRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, GetMappingsViewRequest request, ActionListener<GetMappingsViewResponse> actionListener) {
        // Verify caller has permission on the target index before elevating privileges
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(request.getIndexName());
        client.admin().indices().getMappings(getMappingsRequest, ActionListener.wrap(
                getMappingsResponse -> {
                    this.threadPool.getThreadContext().stashContext();
                    this.mapperService.getMappingsViewAction(request.getIndexName(), request.getRuleTopic(), actionListener);
                },
                actionListener::onFailure
        ));
    }
}