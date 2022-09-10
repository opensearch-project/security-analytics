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
import org.opensearch.client.AdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

public class RuleTopicIndices {
    private static final Logger log = LogManager.getLogger(DetectorIndices.class);

    private final AdminClient client;

    private final ClusterService clusterService;

    public RuleTopicIndices(AdminClient client, ClusterService clusterService) {
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
            client.indices().create(indexRequest, actionListener);
        }
    }

    public boolean ruleTopicIndexExists(String ruleTopicIndex) {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(ruleTopicIndex);
    }
}