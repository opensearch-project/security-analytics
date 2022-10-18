/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;

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

    public static void detectorIndexUpdated() {
        detectorIndexUpdated = true;
    }

    public static void customRuleIndexUpdated() {
        customRuleIndexUpdated = true;
    }

    public static void prePackagedRuleIndexUpdated() {
        prePackagedRuleIndexUpdated = true;
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
}