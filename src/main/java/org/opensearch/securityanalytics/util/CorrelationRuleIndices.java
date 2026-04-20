/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;
import org.opensearch.securityanalytics.model.CorrelationRule;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.maxSystemIndexReplicas;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.minSystemIndexReplicas;

public class CorrelationRuleIndices {
    private static final Logger log = LogManager.getLogger(CorrelationRuleIndices.class);

    private final Client client;

    private final ClusterService clusterService;

    public CorrelationRuleIndices(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public static String correlationRuleIndexMappings() throws IOException {
        return new String(
            Objects.requireNonNull(CorrelationRuleIndices.class.getClassLoader().getResourceAsStream("mappings/correlation-rules.json"))
                .readAllBytes(),
            Charset.defaultCharset()
        );
    }

    public void initCorrelationRuleIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!correlationRuleIndexExists()) {
            Settings indexSettings = Settings.builder()
                    .put("index.hidden", true)
                    .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                    .put("index.auto_expand_replicas", minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                    .build();
            CreateIndexRequest indexRequest = new CreateIndexRequest(CorrelationRule.CORRELATION_RULE_INDEX).mapping(
                correlationRuleIndexMappings()
            ).settings(indexSettings);
            client.admin().indices().create(indexRequest, actionListener);
        } else {
            actionListener.onResponse(new CreateIndexResponse(true, true, CorrelationRule.CORRELATION_RULE_INDEX));
        }
    }

    public boolean correlationRuleIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(CorrelationRule.CORRELATION_RULE_INDEX);
    }
}
