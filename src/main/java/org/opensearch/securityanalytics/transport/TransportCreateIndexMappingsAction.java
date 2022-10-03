/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.securityanalytics.action.CreateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportCreateIndexMappingsAction extends HandledTransportAction<CreateIndexMappingsRequest, AcknowledgedResponse> {
    private MapperService mapperService;
    private ClusterService clusterService;

    @Inject
    public TransportCreateIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            MapperService mapperService,
            ClusterService clusterService
    ) {
        super(CreateIndexMappingsAction.NAME, transportService, actionFilters, CreateIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
    }

    @Override
    protected void doExecute(Task task, CreateIndexMappingsRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        IndexMetadata index = clusterService.state().metadata().index(request.getIndexName());
        if (index == null) {
            actionListener.onFailure(new IllegalStateException("Could not find index [" + request.getIndexName() + "]"));
            return;
        }
        mapperService.createMappingAction(
                request.getIndexName(),
                request.getRuleTopic(),
                request.getAliasMappings(),
                request.getPartial(),
                actionListener
        );
    }
}