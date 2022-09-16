/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.securityanalytics.mapper.MapperApplier;
import org.opensearch.securityanalytics.mapper.model.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.mapper.model.GetIndexMappingsResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportGetIndexMappingsAction extends HandledTransportAction<GetIndexMappingsRequest, GetIndexMappingsResponse> {

    private Client client;
    private MapperApplier mapperApplier;
    private ClusterService clusterService;

    @Inject
    public TransportGetIndexMappingsAction(
            TransportService transportService,
            Client client,
            ActionFilters actionFilters,
            GetIndexMappingsAction getIndexMappingsAction,
            MapperApplier mapperApplier,
            ClusterService clusterService,
            Settings settings
    ) {
        super(getIndexMappingsAction.NAME, transportService, actionFilters, GetIndexMappingsRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.mapperApplier = mapperApplier;
    }

    @Override
    protected void doExecute(Task task, GetIndexMappingsRequest request, ActionListener<GetIndexMappingsResponse> actionListener) {
        IndexMetadata index = clusterService.state().metadata().index(request.getIndexName());
        if (index == null) {
            actionListener.onFailure(new IllegalStateException("Could not find index [" + request.getIndexName() + "]"));
            return;
        }
        mapperApplier.getMappingAction(request.getIndexName(), actionListener);
    }
}