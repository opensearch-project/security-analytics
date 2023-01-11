/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.template.put.PutComponentTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ComponentTemplate;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.MetadataIndexTemplateService;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.securityanalytics.model.CreateMappingResult;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.XContentUtils;

public class IndexTemplateManager {

    private static final Logger log = LogManager.getLogger(IndexTemplateManager.class);

    private static String OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX = ".opensearch-sap-alias-mappings-component-";
    private static String OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX = ".opensearch-sap-alias-mappings-index-template-";

    private IndicesAdminClient indicesClient;
    private ClusterService clusterService;
    private IndexNameExpressionResolver indexNameExpressionResolver;

    public IndexTemplateManager(IndicesAdminClient indicesClient, ClusterService clusterService, IndexNameExpressionResolver indexNameExpressionResolver) {
        this.indicesClient = indicesClient;
        this.clusterService = clusterService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    public void upsertIndexTemplateWithAliasMappings(
            String indexName,
            Collection<CreateMappingResult> createMappingResults,
            ActionListener<AcknowledgedResponse> actionListener
    ) {
        ClusterState state = this.clusterService.state();

        if (IndexUtils.isConcreteIndex(indexName, state)) {
            actionListener.onFailure(SecurityAnalyticsException.wrap(
                    new IllegalStateException("Can't upsert index template for concrete index!"))
            );
            return;
        }

        String concreteIndexName = IndexUtils.getWriteIndex(indexName, state);
        if (concreteIndexName == null) {
            String[] concreteIndices = indexNameExpressionResolver.concreteIndexNames(state, IndicesOptions.LENIENT_EXPAND_OPEN, indexName);
            if (concreteIndices.length == 0) {
                actionListener.onFailure(SecurityAnalyticsException.wrap(
                        new IllegalStateException("Can't upsert index template for concrete index!"))
                );
                return;
            }
            concreteIndexName = IndexUtils.getNewestIndexByCreationDate(concreteIndices, state);
        }

        // Get applied mappings for our concrete index of interest: writeIndex or newest(creation date)
        final String cin = concreteIndexName;
        Optional<CreateMappingResult> createMappingResult =
                createMappingResults.stream()
                        .filter(e -> e.getConcreteIndexName().equals(cin))
                        .findFirst();
        if (createMappingResult.isPresent() == false) {
            actionListener.onFailure(SecurityAnalyticsException.wrap(
                    new IllegalStateException("Can't upsert index template for concrete index!"))
            );
            return;
        }

        Map<String, Object> mappings = createMappingResult.get().getMappings();

        // Upsert component template first
        final String index = concreteIndexName;
        upsertComponentTemplate(indexName, indicesClient, state, mappings, new ActionListener<>() {
            @Override
            public void onResponse(AcknowledgedResponse acknowledgedResponse) {

                if (acknowledgedResponse.isAcknowledged() == false) {
                    log.warn("Upserting component template not ack'd!");
                }
                boolean updateConflictingTemplate = false;
                // Find template which matches input index best
                String templateName =
                        MetadataIndexTemplateService.findV2Template(
                                state.metadata(),
                                normalizeIndexName(indexName),
                                false
                        );
                // If we find conflicting templates(regardless of priority) and that template was created by us,
                // we will silently update index_pattern of that template.
                // Otherwise, we will fail since we don't want to change index_pattern of user created index template
                Map<String, List<String>> conflictingTemplates =
                        MetadataIndexTemplateService.findConflictingV2Templates(
                                state,
                                computeIndexTemplateName(indexName),
                                List.of(computeIndexPattern(indexName))
                        );

                // If there is 1 conflict with our own template, we will update that template's index_pattern field
                if (conflictingTemplates.size() == 1) {
                    String conflictingTemplateName = conflictingTemplates.keySet().iterator().next();
                    if (conflictingTemplateName.startsWith(OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX)) {
                        templateName = conflictingTemplateName;
                        updateConflictingTemplate = true;
                    }
                }

                if (templateName == null && conflictingTemplates.size() > 0) {
                    String errorMessage = "Found conflicting templates: [" +
                            String.join(", ", conflictingTemplates.keySet()) + "]";
                    log.error(errorMessage);
                    actionListener.onFailure(SecurityAnalyticsException.wrap(new IllegalStateException(errorMessage)));
                    return;
                }

                String componentName = computeComponentTemplateName(indexName);

                ComposableIndexTemplate template;
                if (templateName == null) {
                    template = new ComposableIndexTemplate(
                            List.of(computeIndexPattern(indexName)),
                            null,
                            List.of(componentName),
                            null,
                            null,
                            null
                    );
                    templateName = computeIndexTemplateName(indexName);
                } else {
                    template = state.metadata().templatesV2().get(templateName);
                    // Check if we need to append our component to composedOf list
                    if (template.composedOf().contains(componentName) == false) {
                        List<String> newComposedOf;
                        List<String> indexPatterns;
                        if (updateConflictingTemplate) {
                            newComposedOf = new ArrayList<>(template.composedOf());
                            newComposedOf.add(componentName);
                            indexPatterns = List.of(computeIndexPattern(indexName));
                        } else {
                            newComposedOf = List.of(componentName);
                            indexPatterns = template.indexPatterns();
                        }
                        template = new ComposableIndexTemplate(
                                indexPatterns,
                                template.template(),
                                newComposedOf,
                                template.priority(),
                                template.version(),
                                template.metadata(),
                                template.getDataStreamTemplate()
                        );
                    }
                }

                upsertIndexTemplate(
                        indicesClient,
                        templateName == null,
                        template,
                        templateName,
                        actionListener
                );
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });


    }

    private String computeIndexPattern(String indexName) {
        return indexName.endsWith("*") == false ? indexName + "*" : indexName;
    }

    private void upsertIndexTemplate(
            IndicesAdminClient indicesClient,
            boolean create,
            ComposableIndexTemplate indexTemplate,
            String templateName,
            ActionListener<AcknowledgedResponse> actionListener
    ) {

        indicesClient.execute(
                PutComposableIndexTemplateAction.INSTANCE,
                new PutComposableIndexTemplateAction.Request(templateName)
                        .indexTemplate(indexTemplate)
                        .create(create),
                new ActionListener<>() {
                    @Override
                    public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                        actionListener.onResponse(acknowledgedResponse);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        actionListener.onFailure(e);
                    }
                }
        );
    }

    private void upsertComponentTemplate(
            String indexName,
            IndicesAdminClient indicesClient,
            ClusterState state,
            Map<String, Object> mappings,
            ActionListener<AcknowledgedResponse> actionListener
    ) {

        String componentName = computeComponentTemplateName(indexName);
        boolean create = state.metadata().componentTemplates().containsKey(componentName) == false;
        upsertComponentTemplate(componentName, create, indicesClient, mappings, new ActionListener<>() {
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

    private void upsertComponentTemplate(
            String componentName,
            boolean create,
            IndicesAdminClient indicesClient,
            Map<String, Object> mappings,
            ActionListener<AcknowledgedResponse> actionListener
    ) {
        try {

            String mappingsJson = XContentUtils.parseMapToJsonString(mappings);

            ComponentTemplate componentTemplate = new ComponentTemplate(
                    new Template(null, new CompressedXContent(mappingsJson), null),
                    0L,
                    null
            );
            PutComponentTemplateAction.Request req =
                    new PutComponentTemplateAction.Request(componentName)
                            .componentTemplate(componentTemplate)
                            .create(create);

            indicesClient.execute(PutComponentTemplateAction.INSTANCE, req, new ActionListener<>() {
                @Override
                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                    actionListener.onResponse(acknowledgedResponse);
                }

                @Override
                public void onFailure(Exception e) {
                    actionListener.onFailure(e);
                }
            });
        } catch (IOException e) {
            actionListener.onFailure(e);
        }
    }


    private static String normalizeIndexName(String indexName) {
        if (indexName.endsWith("*")) {
            return indexName.substring(0, indexName.length() - 1);
        } else {
            return indexName;
        }
    }
    public static String computeIndexTemplateName(String indexName) {
        return OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX + normalizeIndexName(indexName);
    }

    public static String computeComponentTemplateName(String indexName) {
        if (indexName.endsWith("*")) {
            indexName = indexName.substring(0, indexName.length() - 1);
        }
        return OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX + normalizeIndexName(indexName);
    }
}