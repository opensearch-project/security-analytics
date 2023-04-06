/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.XContentBuilder;


import static org.opensearch.index.mapper.MapperService.SINGLE_MAPPING_NAME;
import static org.opensearch.securityanalytics.mapper.IndexTemplateManager.OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX;
import static org.opensearch.securityanalytics.mapper.IndexTemplateManager.OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX;

public class IndexTemplateUtils {


    public static Set<String> getAllSapComponentTemplates(ClusterState state) {
        Set<String> componentTemplates = new HashSet<>();

        state.metadata().componentTemplates().forEach( (name, instance) -> {
            if (name.startsWith(OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX)) {
                componentTemplates.add(name);
            }
        });
        return componentTemplates;
    }

    public static boolean isSapComposableIndexTemplate(String templateName, ComposableIndexTemplate template) {
        // We don't ever set template field inside ComposableIndexTemplate and our template always starts with OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX
        // If any of these is true, that means that user touched template and we're not owner of it anymore
        if (templateName.startsWith(OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX) == false || template.template() != null) {
            return false;
        }
        // If user added ComponentTemplate then this ComposableIndexTemplate is owned by user
        for (String componentTemplate : template.composedOf()) {
            if (componentTemplate.startsWith(OPENSEARCH_SAP_COMPONENT_TEMPLATE_PREFIX) == false) {
                return false;
            }
        }
        return true;
    }

    public static Map<String, ComposableIndexTemplate> getAllSapComposableIndexTemplates(ClusterState state) {
        Map<String, ComposableIndexTemplate> sapTemplates = new HashMap<>();

        state.metadata().templatesV2().forEach( (name, instance) -> {
            if (isSapComposableIndexTemplate(name, instance)) {
                sapTemplates.put(name, instance);
            }
        });
        return sapTemplates;
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

    public static String normalizeIndexName(String indexName) {
        if (indexName.endsWith("*")) {
            return indexName.substring(0, indexName.length() - 1);
        } else {
            return indexName;
        }
    }

    public static boolean isUserCreatedComposableTemplate(String templateName) {
        return templateName.startsWith(OPENSEARCH_SAP_INDEX_TEMPLATE_PREFIX) == false;
    }

    public static Template copyTemplate(Template template) throws IOException {

        if (template == null) {
            return null;
        }

        CompressedXContent outMappings = null;
        CompressedXContent mappings = template.mappings();
        if (mappings != null) {
            Map<String, Object> mappingsAsMap = XContentHelper.convertToMap(mappings.compressedReference(), true, XContentType.JSON).v2();
            if (mappingsAsMap.containsKey(SINGLE_MAPPING_NAME)) {
                mappingsAsMap = (Map<String, Object>)mappingsAsMap.get(SINGLE_MAPPING_NAME);
            }
            XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.map(mappingsAsMap);

            outMappings = new CompressedXContent(BytesReference.bytes(builder));
        }
        return new Template(
                template.settings(),
                outMappings,
                template.aliases()
        );
    }
}
