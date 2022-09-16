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
import org.opensearch.securityanalytics.mapper.model.GetIndexMappingsResponse;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

public class MapperApplier {

    IndicesAdminClient indicesClient;

    public MapperApplier() {}

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

    public void createMappingAction(String indexName, String ruleTopic, ActionListener<AcknowledgedResponse> actionListener) {

        getMappingAction(indexName, new ActionListener<>() {
            @Override
            public void onResponse(GetIndexMappingsResponse getIndexMappingsResponse) {
                createMappingActionContinuation(getIndexMappingsResponse.getMappings(), ruleTopic, actionListener);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    private void createMappingActionContinuation(ImmutableOpenMap<String, MappingMetadata> indexMappings, String ruleTopic, ActionListener<AcknowledgedResponse> actionListener) {

        PutMappingRequest request;
        try {

            List<String> missingMappings = MapperUtils.validateIndexMappings(indexMappings, ruleTopic);

            if(missingMappings.size() > 0) {
                actionListener.onFailure(
                        new IllegalArgumentException("Not all paths were found in index mappings: " +
                                missingMappings.stream()
                                        .collect(Collectors.joining(", ", "[", "]")))
                );
            }

            String indexName = indexMappings.iterator().next().key;

            request = new PutMappingRequest(indexName).source(
                    MapperFacade.aliasMappings(ruleTopic), XContentType.JSON
            );

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
        } catch (IOException | IllegalArgumentException e) {
            actionListener.onFailure(e);
        }
    }

    public void updateMappingAction(String indexName, String field, String alias) throws IOException {
        PutMappingRequest request = new PutMappingRequest(indexName).source(field, alias);
        indicesClient.putMapping(request);
    }

    public void updateMappingAction(String indexName, String field, String alias, ActionListener<AcknowledgedResponse> actionListener) {
        PutMappingRequest request = new PutMappingRequest(indexName).source(field, alias);
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

    public ImmutableOpenMap<String, MappingMetadata> getMappingAction(String indexName) throws ExecutionException, InterruptedException {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(indexName);
        return indicesClient.getMappings(getMappingsRequest).get().getMappings();
    }

    public void getMappingAction(String indexName, ActionListener<GetIndexMappingsResponse> actionListener) {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(indexName);
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