/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.MapperApplier;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportGetIndexMappingsAction extends HandledTransportAction<GetIndexMappingsRequest, GetIndexMappingsResponse> {
    private MapperApplier mapperApplier;
    private ClusterService clusterService;

    @Inject
    public TransportGetIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            GetIndexMappingsAction getIndexMappingsAction,
            MapperApplier mapperApplier,
            ClusterService clusterService
    ) {
        super(getIndexMappingsAction.NAME, transportService, actionFilters, GetIndexMappingsRequest::new);
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