/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.template.delete.DeleteComponentTemplateAction;
import org.opensearch.action.admin.indices.template.delete.DeleteComposableIndexTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutComponentTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ComponentTemplate;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.MetadataIndexTemplateService;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.regex.Regex;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model.CreateMappingResult;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.XContentUtils;


import static org.opensearch.securityanalytics.mapper.IndexTemplateUtils.computeComponentTemplateName;
import static org.opensearch.securityanalytics.mapper.IndexTemplateUtils.computeIndexTemplateName;
import static org.opensearch.securityanalytics.mapper.IndexTemplateUtils.copyTemplate;
import static org.opensearch.securityanalytics.mapper.IndexTemplateUtils.normalizeIndexName;

public class IndexTemplateManager {

    private static final Logger log = LogManager.getLogger(IndexTemplateManager.class);

    public static String OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX = ".opensearch-sap-alias-mappings-component-";
    public static String OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX = ".opensearch-sap-alias-mappings-index-template-";

    private Client client;
    private ClusterService clusterService;
    private IndexNameExpressionResolver indexNameExpressionResolver;
    private NamedXContentRegistry xContentRegistry;

    public IndexTemplateManager(Client client, ClusterService clusterService, IndexNameExpressionResolver indexNameExpressionResolver, NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.clusterService = clusterService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.xContentRegistry = xContentRegistry;
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
        // Mappings applied to writeIndex or newest index
        Map<String, Object> mappings = createMappingResult.get().getMappings();

        StepListener<AcknowledgedResponse> upsertComponentTemplateStepListener = new StepListener<>();

        // Upsert component template first
        upsertComponentTemplate(indexName, client, state, mappings, upsertComponentTemplateStepListener);

        upsertComponentTemplateStepListener.whenComplete( acknowledgedResponse -> {

            // Find template which matches input index best
            String templateName =
                    MetadataIndexTemplateService.findV2Template(
                            state.metadata(),
                            normalizeIndexName(indexName),
                            false
                    );

            if (templateName == null) {
                // If we find conflicting templates(regardless of priority) and that template was created by us,
                // we will silently update index_pattern of that template.
                // Otherwise, we will fail since we don't want to change index_pattern of user created index template
                Map<String, List<String>> conflictingTemplates =
                        MetadataIndexTemplateService.findConflictingV2Templates(
                                state,
                                computeIndexTemplateName(indexName),
                                List.of(computeIndexPattern(indexName))
                        );
                // If there is 1 conflict which we own (SAP), we will update that template's index_pattern field
                if (conflictingTemplates.size() == 1) {
                    String conflictingTemplateName = conflictingTemplates.keySet().iterator().next();
                    if (conflictingTemplateName.startsWith(OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX)) {
                        templateName = conflictingTemplateName;
                    } else {
                        String errorMessage = "Found conflicting template: [" + conflictingTemplateName + "]";
                        log.error(errorMessage);
                        actionListener.onFailure(SecurityAnalyticsException.wrap(new IllegalStateException(errorMessage)));
                    }
                } else if (conflictingTemplates.size() > 1) {
                    String errorMessage = "Found conflicting templates: [" +
                            String.join(", ", conflictingTemplates.keySet()) + "]";
                    log.error(errorMessage);
                    actionListener.onFailure(SecurityAnalyticsException.wrap(new IllegalStateException(errorMessage)));
                    return;
                }
            }


            String componentName = computeComponentTemplateName(indexName);

            ComposableIndexTemplate template;
            // if we didn't find existing template we will create a new one
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
                // Create new ComposableIndexTemplate
                upsertIndexTemplate(
                        client,
                        true,
                        template,
                        templateName,
                        actionListener
                );
            } else {
                // There is existing template which covers our index pattern.
                // Check if we need to append our component to composedOf list
                template = state.metadata().templatesV2().get(templateName);
                if (template.composedOf().contains(componentName) == false) {
                    List<String> newComposedOf = new ArrayList<>(template.composedOf());
                    List<String> indexPatterns = List.of(computeIndexPattern(indexName));
                    ;
                    newComposedOf.add(componentName);

                    try {
                        template = new ComposableIndexTemplate(
                                indexPatterns,
                                copyTemplate(template.template()),
                                newComposedOf,
                                template.priority(),
                                template.version(),
                                template.metadata(),
                                template.getDataStreamTemplate()
                        );
                        // Update existing ComposableIndexTemplate
                        upsertIndexTemplate(
                                client,
                                false,
                                template,
                                templateName,
                                actionListener
                        );
                    } catch (IOException e) {
                        log.error(e.getMessage());
                        actionListener.onFailure(e);
                    }
                } else {
                    actionListener.onResponse(new AcknowledgedResponse(true));
                }
            }

        }, actionListener::onFailure);

    }

    private String computeIndexPattern(String indexName) {
        return indexName.endsWith("*") == false ? indexName + "*" : indexName;
    }

    private void upsertIndexTemplate(
            Client client,
            boolean create,
            ComposableIndexTemplate indexTemplate,
            String templateName,
            ActionListener<AcknowledgedResponse> actionListener
    ) {

        client.execute(
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
            Client client,
            ClusterState state,
            Map<String, Object> mappings,
            ActionListener<AcknowledgedResponse> actionListener
    ) {

        String componentName = computeComponentTemplateName(indexName);
        boolean create = state.metadata().componentTemplates().containsKey(componentName) == false;
        upsertComponentTemplate(componentName, create, client, mappings, new ActionListener<>() {
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
            Client client,
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

            client.execute(PutComponentTemplateAction.INSTANCE, req, new ActionListener<>() {
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

    public void deleteAllUnusedTemplates(ActionListener<Void> actionListener) {
        Map<String, ComposableIndexTemplate> allSapTemplates = IndexTemplateUtils.getAllSapComposableIndexTemplates(clusterService.state());

        StepListener<Set<String>> getDetectorInputsListener = new StepListener<>();

        DetectorUtils.getAllDetectorInputs(client, xContentRegistry, getDetectorInputsListener);

        getDetectorInputsListener.whenComplete( allInputIndices -> {

            StepListener<Map<String, ComposableIndexTemplate>> doDeleteUnusedTemplatesListener = new StepListener<>();
            doDeleteUnusedTemplates(allSapTemplates, allInputIndices, doDeleteUnusedTemplatesListener);

            doDeleteUnusedTemplatesListener.whenComplete( deletedTemplates -> {
                doDeleteUnusedComponentTemplates(actionListener);
                actionListener.onResponse(null);
            }, actionListener::onFailure);

        }, actionListener::onFailure);
    }

    private void doDeleteUnusedComponentTemplates(ActionListener<Void> actionListener) {
        Set<String> componentTemplates = IndexTemplateUtils.getAllSapComponentTemplates(clusterService.state());
        // Start from set of ALL SAP Component Templates and remove each found in composableIndexTemplates.
        // All component templates remaining in set are unused
        clusterService.state().metadata().templatesV2().forEach( (name, template) ->
                template.composedOf().forEach(componentTemplates::remove)
        );
        // Nothing to delete
        if (componentTemplates.size() == 0) {
            actionListener.onResponse(null);
        }
        // Delete unused component templates
        GroupedActionListener deleteMultipleComponentTemplatesListener = new GroupedActionListener(new ActionListener<Collection<AcknowledgedResponse>>() {
            @Override
            public void onResponse(Collection<AcknowledgedResponse> responses) {
                actionListener.onResponse(null);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        }, componentTemplates.size());

        componentTemplates.forEach((name) ->
                client.execute(
                        DeleteComponentTemplateAction.INSTANCE,
                        new DeleteComponentTemplateAction.Request(name),
                        deleteMultipleComponentTemplatesListener
                )
        );
    }

    private void doDeleteUnusedTemplates(
            Map<String, ComposableIndexTemplate> allSapTemplates,
            Set<String> allDetectorInputIndices,
            ActionListener<Map<String, ComposableIndexTemplate>> actionListener
    ) {
        Map<String, ComposableIndexTemplate> toDeleteTemplates = new HashMap();
        Iterator templateIterator = allSapTemplates.entrySet().iterator();
        while (templateIterator.hasNext()) {
            Map.Entry<String, ComposableIndexTemplate> entry = (Map.Entry)templateIterator.next();
            String templateName = entry.getKey();
            ComposableIndexTemplate template = entry.getValue();

            boolean matched = false;
            for (String index : allDetectorInputIndices) {
                // Skip concrete indices
                if (IndexUtils.isConcreteIndex(index, clusterService.state())) {
                    continue;
                }
                // If any of index patterns of template matches input index, we can finish here and move to next template
                if (template.indexPatterns().stream().anyMatch((pattern) -> Regex.simpleMatch(pattern, normalizeIndexName(index)))) {
                    matched = true;
                    break;
                }
            }
            if (matched == false) {
                toDeleteTemplates.put(templateName, template);
            }
        }
        // Nothing to delete, just return
        if (toDeleteTemplates.size() == 0) {
            actionListener.onResponse(toDeleteTemplates);
            return;
        }
        // Delete all found templates
        GroupedActionListener deleteMultipleTemplatesListener = new GroupedActionListener(new ActionListener<Collection<AcknowledgedResponse>>() {
            @Override
            public void onResponse(Collection<AcknowledgedResponse> responses) {
                actionListener.onResponse(toDeleteTemplates);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        }, toDeleteTemplates.size());

        toDeleteTemplates.forEach((name, template) ->
                client.execute(
                        DeleteComposableIndexTemplateAction.INSTANCE,
                        new DeleteComposableIndexTemplateAction.Request(name),
                        deleteMultipleTemplatesListener
                )
        );

    }
}