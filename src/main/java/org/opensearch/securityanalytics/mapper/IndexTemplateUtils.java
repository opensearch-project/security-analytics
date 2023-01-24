package org.opensearch.securityanalytics.mapper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;

public class IndexTemplateUtils {


    public static Set<String> getAllSapComponentTemplates(ClusterState state) {
        Set<String> componentTemplates = new HashSet<>();

        state.metadata().componentTemplates().forEach( (name, instance) -> {
            if (name.startsWith(IndexTemplateManager.OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX)) {
                componentTemplates.add(name);
            }
        });
        return componentTemplates;
    }

    public static Map<String, ComposableIndexTemplate> getAllSapComposableIndexTemplates(ClusterState state) {
        Map<String, ComposableIndexTemplate> sapTemplates = new HashMap<>();

        state.metadata().templatesV2().forEach( (name, instance) -> {
            if (name.startsWith(IndexTemplateManager.OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX)) {
                sapTemplates.put(name, instance);
            }
        });
        return sapTemplates;
    }

    public static String computeIndexTemplateName(String indexName) {
        return IndexTemplateManager.OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX + normalizeIndexName(indexName);
    }

    public static String computeComponentTemplateName(String indexName) {
        if (indexName.endsWith("*")) {
            indexName = indexName.substring(0, indexName.length() - 1);
        }
        return IndexTemplateManager.OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX + normalizeIndexName(indexName);
    }

    public static String normalizeIndexName(String indexName) {
        if (indexName.endsWith("*")) {
            return indexName.substring(0, indexName.length() - 1);
        } else {
            return indexName;
        }
    }
}
