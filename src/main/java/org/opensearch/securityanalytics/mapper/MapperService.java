/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.get.GetIndexRequest;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.securityanalytics.action.GetMappingsViewResponse;
import org.opensearch.securityanalytics.model.CreateMappingResult;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;


import static org.opensearch.securityanalytics.mapper.MapperUtils.PATH;
import static org.opensearch.securityanalytics.mapper.MapperUtils.PROPERTIES;

public class MapperService {

    private static final Logger log = LogManager.getLogger(MapperService.class);

    private ClusterService clusterService;
    private IndicesAdminClient indicesClient;
    private IndexNameExpressionResolver indexNameExpressionResolver;
    private IndexTemplateManager indexTemplateManager;

    public MapperService() {}

    public MapperService(Client client, ClusterService clusterService, IndexNameExpressionResolver indexNameExpressionResolver, IndexTemplateManager indexTemplateManager) {
        this.indicesClient = client.admin().indices();
        this.clusterService = clusterService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.indexTemplateManager = indexTemplateManager;
    }

    public void createMappingAction(String indexName, String ruleTopic, boolean partial, ActionListener<AcknowledgedResponse> actionListener) {
        this.createMappingAction(indexName, ruleTopic, null, partial, actionListener);
    }

    public void createMappingAction(String indexName, String ruleTopic, String aliasMappings, boolean partial, ActionListener<AcknowledgedResponse> actionListener) {

        // If indexName is Datastream it is enough to apply mappings to writeIndex only
        // since you can't update documents in non-write indices
        String index = indexName;
        boolean shouldUpsertIndexTemplate = IndexUtils.isConcreteIndex(indexName, this.clusterService.state()) == false;
        if (IndexUtils.isDataStream(indexName, this.clusterService.state())) {
            String writeIndex = IndexUtils.getWriteIndex(indexName, this.clusterService.state());
            if (writeIndex != null) {
                index = writeIndex;
            }
        }

        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(index);
        indicesClient.getMappings(getMappingsRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsResponse getMappingsResponse) {
                applyAliasMappings(getMappingsResponse.getMappings(), ruleTopic, aliasMappings, partial, new ActionListener<>() {
                    @Override
                    public void onResponse(Collection<CreateMappingResult> createMappingResponse) {
                        // We will return ack==false if one of the requests returned that
                        // else return ack==true
                        Optional<AcknowledgedResponse> notAckd = createMappingResponse.stream()
                                .map(e -> e.getAcknowledgedResponse())
                                .filter(e -> e.isAcknowledged() == false).findFirst();
                        AcknowledgedResponse ack = new AcknowledgedResponse(
                                notAckd.isPresent() ? false : true
                        );

                        if (shouldUpsertIndexTemplate) {
                            indexTemplateManager.upsertIndexTemplateWithAliasMappings(indexName, createMappingResponse, actionListener);
                        } else {
                            actionListener.onResponse(ack);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        actionListener.onFailure(e);
                    }
                });
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    private void applyAliasMappings(Map<String, MappingMetadata> indexMappings, String ruleTopic, String aliasMappings, boolean partial, ActionListener<Collection<CreateMappingResult>> actionListener) {
        int numOfIndices =  indexMappings.size();

        GroupedActionListener doCreateMappingActionsListener = new GroupedActionListener(new ActionListener<Collection<CreateMappingResult>>() {            @Override
            public void onResponse(Collection<CreateMappingResult> response) {
                actionListener.onResponse(response);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(
                    new SecurityAnalyticsException(
                        "Failed applying mappings to index", RestStatus.INTERNAL_SERVER_ERROR, e
                    )
                );
            }
        }, numOfIndices);

        indexMappings.forEach((k, v) -> {
            String indexName = k;
            MappingMetadata mappingMetadata = v;
            // Try to apply mapping to index
            doCreateMapping(indexName, mappingMetadata, ruleTopic, aliasMappings, partial, doCreateMappingActionsListener);
        });
    }

    /**
     * Applies alias mappings to index.
     * @param indexName Index name
     * @param mappingMetadata Index mappings
     * @param ruleTopic Rule topic spcifying specific alias templates
     * @param aliasMappings User-supplied alias mappings
     * @param partial Partial flag indicating if we should apply mappings partially, in case source index doesn't have all paths specified in alias mappings
     * @param actionListener actionListener used to return response/error
     */
    private void doCreateMapping(
            String indexName,
            MappingMetadata mappingMetadata,
            String ruleTopic,
            String aliasMappings,
            boolean partial,
            ActionListener<CreateMappingResult> actionListener
    ) {

        try {

            String aliasMappingsJSON;
            // aliasMappings parameter has higher priority then ruleTopic
            if (aliasMappings != null) {
                aliasMappingsJSON = aliasMappings;
            } else {
                aliasMappingsJSON = MapperTopicStore.aliasMappings(ruleTopic);
            }

            Pair<List<String>, List<String>> validationResult = MapperUtils.validateIndexMappings(indexName, mappingMetadata, aliasMappingsJSON);
            List<String> missingPathsInIndex = validationResult.getLeft();
            List<String> presentPathsInIndex = validationResult.getRight();

            if(missingPathsInIndex.size() > 0) {
                // If user didn't allow partial apply, we should error out here
                if (!partial) {
                    actionListener.onFailure(
                            new IllegalArgumentException("Not all paths were found in index mappings: " +
                                    missingPathsInIndex.stream()
                                            .collect(Collectors.joining(", ", "[", "]")))
                    );
                }
            }

            // Filter out mappings of sourceIndex fields to which we're applying alias mappings
            Map<String, Object> presentPathsMappings = MapperUtils.getFieldMappingsFlat(mappingMetadata, presentPathsInIndex);
            // Filtered alias mappings -- contains only aliases which are applicable to index:
            //      1. fields in path params exists in index
            //      2. alias isn't named as one of existing fields in index
            Map<String, Object> filteredAliasMappings = filterNonApplicableAliases(
                    mappingMetadata,
                    missingPathsInIndex,
                    aliasMappingsJSON
            );
            Map<String, Object> allMappings = new HashMap<>(presentPathsMappings);
            allMappings.putAll((Map<String, ?>) filteredAliasMappings.get(PROPERTIES));

            Map<String, Object> mappingsRoot = new HashMap<>();
            mappingsRoot.put(PROPERTIES, allMappings);
            // Apply mappings to sourceIndex
            PutMappingRequest request = new PutMappingRequest(indexName).source(filteredAliasMappings);
            indicesClient.putMapping(request, new ActionListener<>() {
                @Override
                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                    //((Map<String, Object>)mappingsRoot.get(PROPERTIES)).putAll(presentPathsMappings);
                    CreateMappingResult result = new CreateMappingResult(
                            acknowledgedResponse,
                            indexName,
                            mappingsRoot
                    );
                    actionListener.onResponse(result);
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

    private Map<String, Object> filterNonApplicableAliases(
            MappingMetadata indexMappingMetadata,
            List<String> missingPathsInIndex,
            String aliasMappingsJSON
    ) throws IOException {
        // Parse aliasMappings JSON into Map
        MappingsTraverser mappingsTraverser = new MappingsTraverser(aliasMappingsJSON, Set.of());
        Map<String, Object> filteredAliasMappings = mappingsTraverser.traverseAndCopyAsFlat();

        List<Pair<String, String>> propertiesToSkip = new ArrayList<>();
        if(missingPathsInIndex.size() > 0) {
            // Filter out missing paths from alias mappings so that our PutMappings request succeeds
            propertiesToSkip.addAll(
                    missingPathsInIndex.stream()
                            .map(e -> Pair.of(PATH, e))
                            .collect(Collectors.toList())
            );
        }
        // Filter out all aliases which name already exists as field in index mappings
        List<String> nonAliasIndexFields = MapperUtils.getAllNonAliasFieldsFromIndex(indexMappingMetadata);
        List<String> aliasFields = MapperUtils.getAllAliases(aliasMappingsJSON);
        Set<String> aliasesToInclude =
                aliasFields.stream()
                        .filter(e -> nonAliasIndexFields.contains(e) == false)
                        .collect(Collectors.toSet());

        boolean excludeSomeAliases = aliasesToInclude.size() < aliasFields.size();
        // check if we need to filter out some properties/nodes in alias mapping
        if (propertiesToSkip.size() > 0 || excludeSomeAliases) {
            mappingsTraverser = new MappingsTraverser(aliasMappingsJSON, propertiesToSkip);
            if (aliasesToInclude.size() > 0) {
                filteredAliasMappings = mappingsTraverser.traverseAndCopyWithFilter(aliasesToInclude);
            } else {
                filteredAliasMappings = mappingsTraverser.traverseAndCopyAsFlat();
            }
        }
        return filteredAliasMappings;
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
        try {
            // We are returning mappings view for only 1 index: writeIndex or latest from the pattern
            resolveConcreteIndex(indexName, new ActionListener<>() {
                @Override
                public void onResponse(String concreteIndex) {
                    doGetMappingAction(indexName, concreteIndex, actionListener);
                }

                @Override
                public void onFailure(Exception e) {
                    actionListener.onFailure(e);
                }
            });


        } catch (IOException e) {
            throw SecurityAnalyticsException.wrap(e);
        }
    }

    public void doGetMappingAction(String indexName, String concreteIndexName, ActionListener<GetIndexMappingsResponse> actionListener) {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(concreteIndexName);
        indicesClient.getMappings(getMappingsRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsResponse getMappingsResponse) {
                try {
                    // Extract MappingMetadata
                    MappingMetadata mappingMetadata = getMappingsResponse.mappings().entrySet().iterator().next().getValue();
                    // List of all found applied aliases on index
                    Set<String> appliedAliases = new HashSet<>();
                    // Get list of alias -> path pairs from index mappings
                    List<Pair<String, String>> indexAliasPathPairs = MapperUtils.getAllAliasPathPairs(mappingMetadata);

                    Map<String, String> aliasMappingsMap = MapperTopicStore.getAliasMappingsMap();
                    for (String mapperTopic : aliasMappingsMap.keySet()) {
                        // Get stored Alias Mappings as JSON string
                        String aliasMappingsJson = MapperTopicStore.aliasMappings(mapperTopic);
                        // Get list of alias -> path pairs from stored alias mappings
                        List<Pair<String, String>> aliasPathPairs = MapperUtils.getAllAliasPathPairs(aliasMappingsJson);
                        // Try to find any alias mappings in index mappings which are present in stored alias mappings
                        for (Pair<String, String> p1 : indexAliasPathPairs) {
                            for (Pair<String, String> p2 : aliasPathPairs) {
                                // Match by alias only here since user can match alias to some other path
                                if (p1.getKey().equals(p2.getKey())) {
                                    // Maintain list of found alias mappings
                                    appliedAliases.add(p1.getKey());
                                }
                            }
                        }
                    }

                    if (appliedAliases.size() == 0) {
                        actionListener.onFailure(SecurityAnalyticsException.wrap(
                                new OpenSearchStatusException("No applied aliases found", RestStatus.NOT_FOUND))
                        );
                        return;
                    }

                    // Traverse mappings and do copy with excluded type=alias properties
                    MappingsTraverser mappingsTraverser = new MappingsTraverser(mappingMetadata);
                    // Resulting mapping after filtering
                    Map<String, Object> filteredMapping = mappingsTraverser.traverseAndCopyWithFilter(appliedAliases);


                    // Construct filtered mappings and return them as result
                    Map<String, MappingMetadata> outIndexMappings = new HashMap<>();
                    Map<String, Object> root = Map.of(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, filteredMapping);
                    MappingMetadata outMappingMetadata = new MappingMetadata(org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME, root);
                    outIndexMappings.put(indexName, outMappingMetadata);

                    actionListener.onResponse(new GetIndexMappingsResponse(outIndexMappings));
                } catch (IOException e) {
                    actionListener.onFailure(e);
                }
            }
                @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    public void getMappingsViewAction(
            String indexName,
            String mapperTopic,
            ActionListener<GetMappingsViewResponse> actionListener
    ) {
        try {
            // We are returning mappings view for only 1 index: writeIndex or latest from the pattern
            resolveConcreteIndex(indexName, new ActionListener<>() {
                @Override
                public void onResponse(String concreteIndex) {
                    doGetMappingsView(mapperTopic, actionListener, concreteIndex);
                }

                @Override
                public void onFailure(Exception e) {
                    actionListener.onFailure(e);
                }
            });


        } catch (IOException e) {
            throw SecurityAnalyticsException.wrap(e);
        }
    }

    /**
     * Constructs Mappings View of index
     * @param mapperTopic Mapper Topic describing set of alias mappings
     * @param actionListener Action Listener
     * @param concreteIndex Concrete Index name for which we're computing Mappings View
     */
    private void doGetMappingsView(String mapperTopic, ActionListener<GetMappingsViewResponse> actionListener, String concreteIndex) {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(concreteIndex);
        indicesClient.getMappings(getMappingsRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetMappingsResponse getMappingsResponse) {
                try {
                    // Extract MappingMetadata from GET _mapping response
                    MappingMetadata mappingMetadata = getMappingsResponse.mappings().entrySet().iterator().next().getValue();
                    // Get list of all non-alias fields in index
                    List<String> allFieldsFromIndex = MapperUtils.getAllNonAliasFieldsFromIndex(mappingMetadata);
                    // Get stored Alias Mappings as JSON string
                    String aliasMappingsJson = MapperTopicStore.aliasMappings(mapperTopic);
                    // Get list of alias -> path pairs from stored alias mappings
                    List<Pair<String, String>> aliasPathPairs = MapperUtils.getAllAliasPathPairs(aliasMappingsJson);
                    // List of all found applied aliases on index
                    List<String> applyableAliases = new ArrayList<>();
                    // List of paths of found
                    List<String> pathsOfApplyableAliases = new ArrayList<>();
                    // List of unapplayable aliases
                    List<String> unmappedFieldAliases = new ArrayList<>();

                    for (Pair<String, String> p : aliasPathPairs) {
                        String alias = p.getKey();
                        String path = p.getValue();
                        if (allFieldsFromIndex.contains(path)) {
                            // Maintain list of found paths in index
                            applyableAliases.add(alias);
                            pathsOfApplyableAliases.add(path);
                        } else if (allFieldsFromIndex.contains(alias) == false)  {
                            // we don't want to send back aliases which have same name as existing field in index
                            unmappedFieldAliases.add(alias);
                        }
                    }
                    // Gather all applyable alias mappings
                    Map<String, Object> aliasMappings =
                            MapperUtils.getAliasMappingsWithFilter(aliasMappingsJson, applyableAliases);
                    // Unmapped fields from index for which we don't have alias to apply to
                    List<String> unmappedIndexFields = allFieldsFromIndex
                            .stream()
                            .filter(e -> pathsOfApplyableAliases.contains(e) == false)
                            .collect(Collectors.toList());

                    actionListener.onResponse(
                            new GetMappingsViewResponse(aliasMappings, unmappedIndexFields, unmappedFieldAliases)
                    );
                } catch (Exception e) {
                    actionListener.onFailure(e);
                }
            }
            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    /**
     * Given index name, resolves it to single concrete index, depending on what initial <code>indexName</code> is.
     * In case of Datastream or Alias, WriteIndex would be returned. In case of index pattern, newest index by creation date would be returned.
     * @param indexName Datastream, Alias, index patter or concrete index
     * @param actionListener Action Listener
     * @throws IOException
     */
    private void resolveConcreteIndex(String indexName, ActionListener<String> actionListener) throws IOException {

        indicesClient.getIndex((new GetIndexRequest()).indices(indexName), new ActionListener<>() {
            @Override
            public void onResponse(GetIndexResponse getIndexResponse) {
                String[] indices = getIndexResponse.indices();
                if (indices.length == 0) {
                    actionListener.onFailure(
                            SecurityAnalyticsException.wrap(
                                    new IllegalArgumentException("Invalid index name: [" + indexName + "]")
                            )
                    );
                } else if (indices.length == 1) {
                    actionListener.onResponse(indices[0]);
                } else if (indices.length > 1) {
                    String writeIndex = IndexUtils.getWriteIndex(indexName, MapperService.this.clusterService.state());
                    if (writeIndex != null) {
                        actionListener.onResponse(writeIndex);
                    } else {
                        actionListener.onResponse(
                            IndexUtils.getNewestIndexByCreationDate(indices, MapperService.this.clusterService.state())
                        );
                    }
                }
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });

    }

    void setIndicesAdminClient(IndicesAdminClient client) {
        this.indicesClient = client;
    }
    void setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
    }

    public void setIndexNameExpressionResolver(IndexNameExpressionResolver indexNameExpressionResolver) {
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    public void setIndexTemplateManager(IndexTemplateManager indexTemplateManager) {
        this.indexTemplateManager = indexTemplateManager;
    }
}