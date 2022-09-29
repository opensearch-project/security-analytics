/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

public class RuleTopicIndices {
    private static final Logger log = LogManager.getLogger(DetectorIndices.class);

    private final Client client;

    private final ClusterService clusterService;

    public RuleTopicIndices(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public static String ruleTopicIndexMappings() throws IOException {
        return new String(Objects.requireNonNull(DetectorIndices.class.getClassLoader().getResourceAsStream("mappings/detector-queries.json")).readAllBytes(), Charset.defaultCharset());
    }

    public static String ruleTopicIndexSettings() throws IOException {
        return new String(Objects.requireNonNull(DetectorIndices.class.getClassLoader().getResourceAsStream("mappings/detector-settings.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initRuleTopicIndex(String ruleTopicIndex, ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!ruleTopicIndexExists(ruleTopicIndex)) {
            CreateIndexRequest indexRequest = new CreateIndexRequest(ruleTopicIndex)
                    .mapping(ruleTopicIndexMappings())
                    .settings(Settings.builder().loadFromSource(ruleTopicIndexSettings(), XContentType.JSON).build());
            client.admin().indices().create(indexRequest, actionListener);
        } else {
            actionListener.onResponse(new CreateIndexResponse(true, true, ruleTopicIndex));
        }
    }

    public void deleteRuleTopicIndex(String ruleTopicIndex, ActionListener<AcknowledgedResponse> actionListener) throws IOException {
        if (ruleTopicIndexExists(ruleTopicIndex)) {
            DeleteIndexRequest request = new DeleteIndexRequest(ruleTopicIndex);
            client.admin().indices().delete(request, actionListener);
        }
    }

    public void countQueries(String ruleTopicIndex, ActionListener<SearchResponse> listener) {
        SearchRequest request = new SearchRequest(ruleTopicIndex)
                .source(new SearchSourceBuilder().size(0));
        client.search(request, listener);
    }

    public boolean ruleTopicIndexExists(String ruleTopicIndex) {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(ruleTopicIndex);
    }
}