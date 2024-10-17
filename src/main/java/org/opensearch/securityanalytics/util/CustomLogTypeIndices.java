/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.health.ClusterIndexHealth;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.logtype.LogTypeService;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.maxSystemIndexReplicas;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.minSystemIndexReplicas;

public class CustomLogTypeIndices {

    private static final Logger log = LogManager.getLogger(CustomLogTypeIndices.class);


    private final AdminClient client;

    private final ClusterService clusterService;

    public CustomLogTypeIndices(AdminClient client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public static String customLogTypeMappings() throws IOException {
        return new String(Objects.requireNonNull(CustomLogTypeIndices.class.getClassLoader().getResourceAsStream("mappings/log_type_config_mapping.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initCustomLogTypeIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!customLogTypeIndexExists()) {
            // Security Analytics log types index is small. 1 primary shard is enough
            Settings indexSettings = Settings.builder()
                    .put("index.hidden", true)
                    .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                    .put("index.auto_expand_replicas", minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                    .build();
            CreateIndexRequest indexRequest = new CreateIndexRequest(LogTypeService.LOG_TYPE_INDEX)
                    .mapping(customLogTypeMappings())
                    .settings(indexSettings);
            client.indices().create(indexRequest, actionListener);
        }
    }

    public boolean customLogTypeIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(LogTypeService.LOG_TYPE_INDEX);
    }

    public ClusterIndexHealth customLogTypeIndexHealth() {
        ClusterIndexHealth indexHealth = null;

        if (customLogTypeIndexExists()) {
            IndexRoutingTable indexRoutingTable = clusterService.state().routingTable().index(LogTypeService.LOG_TYPE_INDEX);
            IndexMetadata indexMetadata = clusterService.state().metadata().index(LogTypeService.LOG_TYPE_INDEX);

            indexHealth = new ClusterIndexHealth(indexMetadata, indexRoutingTable);
        }
        return indexHealth;
    }
}