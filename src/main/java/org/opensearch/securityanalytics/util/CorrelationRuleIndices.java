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
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;
import org.opensearch.securityanalytics.model.CorrelationRule;

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
            CreateIndexRequest indexRequest = new CreateIndexRequest(CorrelationRule.CORRELATION_RULE_INDEX).mapping(
                correlationRuleIndexMappings()
            ).settings(Settings.builder().put("index.hidden", true).build());
            client.admin().indices().create(indexRequest, actionListener);
        }
    }

    public boolean correlationRuleIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(CorrelationRule.CORRELATION_RULE_INDEX);
    }
}
