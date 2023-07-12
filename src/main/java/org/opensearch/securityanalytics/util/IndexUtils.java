/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.SortedMap;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class IndexUtils {

    private static final String _META = "_meta";
    private static final Integer NO_SCHEMA_VERSION = 0;
    private static final String SCHEMA_VERSION = "schema_version";

    public static Boolean detectorIndexUpdated = false;
    public static Boolean customRuleIndexUpdated = false;
    public static Boolean prePackagedRuleIndexUpdated = false;
    public static Boolean correlationIndexUpdated = false;
    public static Boolean correlationRuleIndexUpdated = false;

    public static void detectorIndexUpdated() {
        detectorIndexUpdated = true;
    }

    public static void customRuleIndexUpdated() {
        customRuleIndexUpdated = true;
    }

    public static void prePackagedRuleIndexUpdated() {
        prePackagedRuleIndexUpdated = true;
    }

    public static void correlationIndexUpdated() { correlationIndexUpdated = true; }

    public static void correlationRuleIndexUpdated() {
        correlationRuleIndexUpdated = true;
    }

    public static Integer getSchemaVersion(String mapping) throws IOException {
        XContentParser xcp = XContentType.JSON.xContent().createParser(
                NamedXContentRegistry.EMPTY,
                LoggingDeprecationHandler.INSTANCE, mapping
        );

        while (!xcp.isClosed()) {
            XContentParser.Token token = xcp.currentToken();
            if (token != null && token != XContentParser.Token.END_OBJECT && token != XContentParser.Token.START_OBJECT) {
                if (!Objects.equals(xcp.currentName(), _META)) {
                    xcp.nextToken();
                    xcp.skipChildren();
                } else {
                    while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                        switch (xcp.currentName()) {
                            case SCHEMA_VERSION:
                                int version = xcp.intValue();
                                if (version < 0) {
                                    throw new IllegalArgumentException(String.format(Locale.getDefault(), "%s cannot be negative", SCHEMA_VERSION));
                                }
                                return version;
                            default:
                                xcp.nextToken();
                        }
                    }
                }
            }
            xcp.nextToken();
        }
        return NO_SCHEMA_VERSION;
    }

    public static Boolean shouldUpdateIndex(IndexMetadata index, String mapping) throws IOException {
        Integer oldVersion = NO_SCHEMA_VERSION;
        Integer newVersion = getSchemaVersion(mapping);

        Map<String, Object> indexMapping = index.mapping().sourceAsMap();
        if (indexMapping != null && indexMapping.containsKey(_META) && indexMapping.get(_META) instanceof HashMap<?, ?>) {
            Map<?, ?> metaData = (HashMap<?, ?>) indexMapping.get(_META);
            if (metaData.containsKey(SCHEMA_VERSION)) {
                oldVersion = (Integer) metaData.get(SCHEMA_VERSION);
            }
        }
        return newVersion > oldVersion;
    }

    public static void updateIndexMapping(
            String index,
            String mapping,
            ClusterState clusterState,
            IndicesAdminClient client,
            ActionListener<AcknowledgedResponse> actionListener
    ) throws IOException {
        if (clusterState.metadata().indices().containsKey(index)) {
            if (shouldUpdateIndex(clusterState.metadata().index(index), mapping)) {
                PutMappingRequest putMappingRequest = new PutMappingRequest(index).source(mapping, XContentType.JSON);
                client.putMapping(putMappingRequest, actionListener);
            } else {
                actionListener.onResponse(new AcknowledgedResponse(true));
            }
        }
    }

    public static boolean isDataStream(String name, ClusterState clusterState) {
        return clusterState.getMetadata().dataStreams().containsKey(name);
    }
    public static boolean isAlias(String indexName, ClusterState clusterState) {
        return clusterState.getMetadata().hasAlias(indexName);
    }
    public static String getWriteIndex(String indexName, ClusterState clusterState) {
        if(isAlias(indexName, clusterState) || isDataStream(indexName, clusterState)) {
            IndexMetadata metadata = clusterState.getMetadata()
                    .getIndicesLookup()
                    .get(indexName).getWriteIndex();
            if (metadata != null) {
                return metadata.getIndex().getName();
            }
        }
        return null;
    }

    public static boolean isConcreteIndex(String indexName, ClusterState clusterState) {
        IndexAbstraction indexAbstraction = clusterState.getMetadata()
                .getIndicesLookup()
                .get(indexName);

        if (indexAbstraction != null) {
            return indexAbstraction.getType() == IndexAbstraction.Type.CONCRETE_INDEX;
        } else {
            return false;
        }
    }

    public static String getNewestIndexByCreationDate(String[] concreteIndices, ClusterState clusterState) {
        final SortedMap<String, IndexAbstraction> lookup = clusterState.getMetadata().getIndicesLookup();
        long maxCreationDate = Long.MIN_VALUE;
        String newestIndex = null;
        for (String indexName : concreteIndices) {
            IndexAbstraction index = lookup.get(indexName);
            IndexMetadata indexMetadata = clusterState.getMetadata().index(indexName);
            if(index != null && index.getType() == IndexAbstraction.Type.CONCRETE_INDEX) {
                if (indexMetadata.getCreationDate() > maxCreationDate) {
                    maxCreationDate = indexMetadata.getCreationDate();
                    newestIndex = indexName;
                }
            }
        }
        return newestIndex;
    }

    public static String getNewIndexByCreationDate(ClusterState state, IndexNameExpressionResolver i, String index) {
        String[] strings = i.concreteIndexNames(state, IndicesOptions.LENIENT_EXPAND_OPEN, index);
        return getNewestIndexByCreationDate(strings, state);
    }

}