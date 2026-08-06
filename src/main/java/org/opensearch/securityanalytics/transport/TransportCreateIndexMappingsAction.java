/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.securityanalytics.action.CreateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.Map;

public class TransportCreateIndexMappingsAction extends HandledTransportAction<CreateIndexMappingsRequest, AcknowledgedResponse> {
    private MapperService mapperService;
    private ClusterService clusterService;

    private final ThreadPool threadPool;
    private final Client client;


    @Inject
    public TransportCreateIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ThreadPool threadPool,
            MapperService mapperService,
            ClusterService clusterService,
            Client client
    ) {
        super(CreateIndexMappingsAction.NAME, transportService, actionFilters, CreateIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, CreateIndexMappingsRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        // Verify caller has indices:admin/mapping/put on the target index before elevating privileges.
        // Issues a no-op PutMappingRequest (empty properties) as the caller — the security plugin
        // checks the permission naturally without stashContext, so unauthorized users get 403.
        PutMappingRequest putMappingRequest = new PutMappingRequest(request.getIndexName())
                .source(Map.of("properties", Map.of()));
        client.admin().indices().putMapping(putMappingRequest, ActionListener.wrap(
                putMappingResponse -> {
                    this.threadPool.getThreadContext().stashContext();
                    mapperService.createMappingAction(
                            request.getIndexName(),
                            request.getRuleTopic(),
                            request.getAliasMappings(),
                            request.getPartial(),
                            actionListener
                    );
                },
                actionListener::onFailure
        ));
    }
}
