/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.clustermanager.TransportClusterManagerNodeAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.block.ClusterBlockLevel;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.securityanalytics.mapper.MapperApplier;
import org.opensearch.securityanalytics.mapper.MapperFacade;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;

public class TransportUpdateIndexMappingsAction extends TransportClusterManagerNodeAction<UpdateIndexMappingsRequest, AcknowledgedResponse> {

    private Client client;
    private MapperApplier mapperApplier;

    @Inject
    public TransportUpdateIndexMappingsAction(
            ThreadPool threadPool,
            ClusterService clusterService,
            TransportService transportService,
            ActionFilters actionFilters,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Client client
    ) {
        super(
                UpdateIndexMappingsAction.NAME,
                transportService,
                clusterService,
                threadPool,
                actionFilters,
                UpdateIndexMappingsRequest::new,
                indexNameExpressionResolver
        );
        this.client = client;
        this.mapperApplier = new MapperApplier(client);
    }

    @Override
    protected String executor() {
        return ThreadPool.Names.SAME;
    }

    @Override
    protected AcknowledgedResponse read(StreamInput in) throws IOException {
        return new AcknowledgedResponse(in);
    }

    @Override
    protected void masterOperation(
            UpdateIndexMappingsRequest request,
            ClusterState state,
            ActionListener<AcknowledgedResponse> actionListener) throws IOException {

        IndexMetadata index = state.metadata().index(request.indexName);
        if (index == null) {
            actionListener.onFailure(new IllegalStateException("Could not find index [" + request.indexName + "]"));
            return;
        }

        mapperApplier.createMappingAction(request.indexName, request.ruleTopic);
        actionListener.onResponse(new AcknowledgedResponse(true));
    }

    @Override
    protected ClusterBlockException checkBlock(UpdateIndexMappingsRequest request, ClusterState state) {
        return state.blocks().indicesBlockedException(ClusterBlockLevel.METADATA_WRITE, new String[]{request.indexName});
    }
}
