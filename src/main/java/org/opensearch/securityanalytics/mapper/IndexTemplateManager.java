package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
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
                // Find template which matches input index best
                String templateName =
                        MetadataIndexTemplateService.findV2Template(
                                state.metadata(),
                                index,
                                false
                        );
                String componentName = computeComponentTemplateName(indexName);

                ComposableIndexTemplate template;
                if (templateName == null) {
                    template = new ComposableIndexTemplate(
                            List.of(indexName.endsWith("*") == false ? indexName + "*": indexName),
                            null,
                            List.of(componentName),
                            null,
                            null,
                            null
                    );
                } else {
                    template = state.metadata().templatesV2().get(templateName);
                }

                upsertIndexTemplate(
                        indicesClient,
                        templateName == null,
                        template,
                        indexName,
                        componentName,
                        actionListener
                );
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });


    }

    private void upsertIndexTemplate(IndicesAdminClient indicesClient, boolean create, ComposableIndexTemplate indexTemplate, String indexName, String componentName, ActionListener<AcknowledgedResponse> actionListener) {

        indicesClient.execute(
                PutComposableIndexTemplateAction.INSTANCE,
                new PutComposableIndexTemplateAction.Request(OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX + indexName)
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
                afterComponentTemplateUpsert(componentName, indexName, state, actionListener);
            }

            @Override
            public void onFailure(Exception e) {

            }
        });
    }

    private void afterComponentTemplateUpsert(String componentName, String indexName, ClusterState state, ActionListener actionListener) {

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

    private String computeComponentTemplateName(String indexName) {
        if (indexName.endsWith("*")) {
            indexName = indexName.substring(0, indexName.length() - 2);
        }
        return OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX + indexName;
    }
}
