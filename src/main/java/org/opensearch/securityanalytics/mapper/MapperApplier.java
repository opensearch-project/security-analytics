/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.securityanalytics.mapper.action.mapping.GetIndexMappingsResponse;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class MapperApplier {

    IndicesAdminClient indicesClient;

    public MapperApplier(Client client) {
        this.indicesClient = client.admin().indices();
    }

    public PutMappingRequest createMappingAction(String logIndex, String ruleTopic) throws IOException {
        PutMappingRequest request = new PutMappingRequest(logIndex).source(
                MapperFacade.aliasMappings(ruleTopic), XContentType.JSON
        );
        indicesClient.putMapping(request);
        return request;
    }

    public PutMappingRequest createMappingAction(String logIndex, String ruleTopic, ActionListener<AcknowledgedResponse> actionListener) {
        PutMappingRequest request = null;
        try {
            request = new PutMappingRequest(logIndex).source(
                    MapperFacade.aliasMappings(ruleTopic), XContentType.JSON
            );
        } catch (IOException e) {
            actionListener.onFailure(e);
        }
        indicesClient.putMapping(request, new ActionListener<>() {
            @Override
            public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                actionListener.onResponse(acknowledgedResponse);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
        return request;
    }

    public void updateMappingAction(String logIndex, String field, String alias) throws IOException {
        PutMappingRequest request = new PutMappingRequest(logIndex).source(field, alias);
        indicesClient.putMapping(request);
    }

    public void updateMappingAction(String logIndex, String field, String alias, ActionListener<AcknowledgedResponse> actionListener) {
        PutMappingRequest request = new PutMappingRequest(logIndex).source(field, alias);
        indicesClient.putMapping(request, new ActionListener<>() {
            @Override
            public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                actionListener.onResponse(acknowledgedResponse);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    public ImmutableOpenMap<String, MappingMetadata> readMappingAction(String logIndex) throws ExecutionException, InterruptedException {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(logIndex);
        return indicesClient.getMappings(getMappingsRequest).get().getMappings();
    }

    public void readMappingAction(String logIndex, ActionListener<GetIndexMappingsResponse> actionListener) {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(logIndex);
        indicesClient.getMappings(getMappingsRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsResponse getMappingsResponse) {
                actionListener.onResponse(new GetIndexMappingsResponse(getMappingsResponse.mappings()));
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }
}