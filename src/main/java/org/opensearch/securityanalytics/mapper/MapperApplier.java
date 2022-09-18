/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import org.apache.commons.lang3.tuple.Pair;
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
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.mapper.model.GetIndexMappingsResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.mapper.MapperUtils.*;

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

    public void setIndicesAdminClient(IndicesAdminClient client) {
        this.indicesClient = client;
    }

    public void createMappingAction(String indexName, String ruleTopic, boolean partial, ActionListener<AcknowledgedResponse> actionListener) {

        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(indexName);
        indicesClient.getMappings(getMappingsRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsResponse getMappingsResponse) {
                createMappingActionContinuation(getMappingsResponse.getMappings(), ruleTopic, partial, actionListener);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    private void createMappingActionContinuation(ImmutableOpenMap<String, MappingMetadata> indexMappings, String ruleTopic, boolean partial, ActionListener<AcknowledgedResponse> actionListener) {

        PutMappingRequest request;
        try {

            String indexName = indexMappings.iterator().next().key;
            String aliasMappingsJSON = MapperFacade.aliasMappings(ruleTopic);

            List<String> missingMappings = MapperUtils.validateIndexMappings(indexMappings, aliasMappingsJSON);

            if(missingMappings.size() > 0) {
                // If user didn't allow partial apply, we should error out here
                if (partial == false) {
                    actionListener.onFailure(
                            new IllegalArgumentException("Not all paths were found in index mappings: " +
                                    missingMappings.stream()
                                            .collect(Collectors.joining(", ", "[", "]")))
                    );
                }
                // Filter out missing paths from alias mappings so that our PutMappings request succeeds
                List<Pair<String, String>> pathsToSkip =
                        missingMappings.stream()
                                .map(e -> Pair.of(PATH, e))
                                .collect(Collectors.toList());
                MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJSON, pathsToSkip);
                Map<String, Object> filteredMappings = mappingsTraverser.traverseAndShallowCopy();

                request = new PutMappingRequest(indexName).source(filteredMappings);
            } else {
                request = new PutMappingRequest(indexName).source(
                        MapperFacade.aliasMappings(ruleTopic), XContentType.JSON
                );
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
        } catch (IOException | IllegalArgumentException e) {
            actionListener.onFailure(e);
        }
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

    public void getMappingAction(String indexName, ActionListener<GetIndexMappingsResponse> actionListener) {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(indexName);
        indicesClient.getMappings(getMappingsRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsResponse getMappingsResponse) {
                try {
                    // Extract indexName and MappingMetadata
                    String indexName = getMappingsResponse.mappings().iterator().next().key;
                    MappingMetadata mappingMetadata = getMappingsResponse.mappings().iterator().next().value;
                    // List of all found applied aliases on index
                    List<String> appliedAliases = new ArrayList<>();
                    // Get list of alias -> path pairs from index mappings
                    List<Pair<String, String>> indexAliasPathPairs = MapperUtils.getAllAliasPathPairs(mappingMetadata);

                    Map<String, String> aliasMappingsMap = MapperFacade.getAliasMappingsMap();
                    for (String mapperTopic : aliasMappingsMap.keySet()) {
                        // Get stored Alias Mappings as JSON string
                        String aliasMappingsJson = MapperFacade.aliasMappings(mapperTopic);
                        // Get list of alias -> path pairs from stored alias mappings
                        List<Pair<String, String>> aliasPathPairs = MapperUtils.getAllAliasPathPairs(aliasMappingsJson);
                        // Try to find any alias mappings in index mappings which are present in stored alias mappings
                        for (Pair<String, String> p1 : indexAliasPathPairs) {
                            for (Pair<String, String> p2 : aliasPathPairs) {
                                if (p1.getKey().equals(p2.getKey()) && p1.getValue().equals(p2.getValue())) {
                                    // Maintain list of found alias mappings
                                    appliedAliases.add(p1.getKey());
                                }
                            }
                        }
                        // If we found all aliases we can stop searching further
                        if (indexAliasPathPairs.size() == appliedAliases.size()) {
                            break;
                        }
                    }
                    // Traverse mappings and do copy with excluded type=alias properties
                    MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
                    // Resulting properties after filtering
                    Map<String, Object> filteredProperties = new HashMap<>();

                    mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
                        @Override
                        public void onLeafVisited(MappingsTraverser.Node node) {
                            // Skip everything except aliases we found
                            if (appliedAliases.contains(node.currentPath) == false) {
                                return;
                            }
                            MappingsTraverser.Node n = node;
                            while (n.parent != null) {
                                n = n.parent;
                            }
                            if (n == null) {
                                n = node;
                            }
                            filteredProperties.put(n.getNodeName(), n.getProperties());
                        }

                        @Override
                        public void onError(String error) {
                            throw new IllegalArgumentException("");
                        }
                    });
                    mappingsTraverser.traverse();
                    // Construct filtered mappings and return them as result
                    ImmutableOpenMap.Builder<String, MappingMetadata> outIndexMappings = ImmutableOpenMap.builder();
                    Map<String, Object> outRootProperties = Map.of(PROPERTIES, filteredProperties);
                    Map<String, Object> root = Map.of(MapperService.SINGLE_MAPPING_NAME, outRootProperties);
                    MappingMetadata outMappingMetadata = new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, root);
                    outIndexMappings.put(indexName, outMappingMetadata);

                    actionListener.onResponse(new GetIndexMappingsResponse(outIndexMappings.build()));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
                @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }
}