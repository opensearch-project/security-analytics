/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.securityanalytics.mapper.MapperApplier;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;

public class TransportUpdateIndexMappingsAction extends HandledTransportAction<UpdateIndexMappingsRequest, AcknowledgedResponse> {

    private Client client;
    private MapperApplier mapperApplier;
    private ClusterService clusterService;

    @Inject
    public TransportUpdateIndexMappingsAction(
            TransportService transportService,
            Client client,
            ActionFilters actionFilters,
            UpdateIndexMappingsAction updateIndexMappingsAction,
            MapperApplier mapperApplier,
            ClusterService clusterService,
            Settings settings
    ) {
        super(updateIndexMappingsAction.NAME, transportService, actionFilters, UpdateIndexMappingsRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.mapperApplier = mapperApplier;
    }

    @Override
    protected void doExecute(Task task, UpdateIndexMappingsRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        try {
            IndexMetadata index = clusterService.state().metadata().index(request.indexName);
            if (index == null) {
                actionListener.onFailure(new IllegalStateException("Could not find index [" + request.indexName + "]"));
                return;
            }
            mapperApplier.updateMappingAction(
                    request.indexName,
                    request.alias,
                    buildAliasJson(request.field),
                    actionListener)
            ;
        } catch (IOException e) {
            actionListener.onFailure(e);
        }
    }

    private String buildAliasJson(String fieldName) throws IOException {
        return "type=alias,path=" + fieldName;
    }
}