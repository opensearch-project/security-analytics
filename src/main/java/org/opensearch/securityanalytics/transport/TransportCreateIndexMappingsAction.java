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
import org.opensearch.securityanalytics.mapper.MapperApplier;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportCreateIndexMappingsAction extends HandledTransportAction<CreateIndexMappingsRequest, AcknowledgedResponse> {
    private MapperApplier mapperApplier;
    private ClusterService clusterService;

    @Inject
    public TransportCreateIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            MapperApplier mapperApplier,
            ClusterService clusterService
    ) {
        super(CreateIndexMappingsAction.NAME, transportService, actionFilters, CreateIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperApplier = mapperApplier;
    }

    @Override
    protected void doExecute(Task task, CreateIndexMappingsRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        IndexMetadata index = clusterService.state().metadata().index(request.getIndexName());
        if (index == null) {
            actionListener.onFailure(new IllegalStateException("Could not find index [" + request.getIndexName() + "]"));
            return;
        }
        mapperApplier.createMappingAction(request.getIndexName(), request.getRuleTopic(), request.getPartial(), actionListener);
    }
}