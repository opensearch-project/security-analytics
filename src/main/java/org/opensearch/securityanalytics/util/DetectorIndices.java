/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.health.ClusterIndexHealth;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.maxSystemIndexReplicas;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.minSystemIndexReplicas;

public class DetectorIndices {

    private static final Logger log = LogManager.getLogger(DetectorIndices.class);

    private final AdminClient client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    public DetectorIndices(AdminClient client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    public static String detectorMappings() throws IOException {
        return new String(Objects.requireNonNull(DetectorIndices.class.getClassLoader().getResourceAsStream("mappings/detectors.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initDetectorIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!detectorIndexExists()) {
            Settings indexSettings = Settings.builder()
                    .put("index.hidden", true)
                    .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                    .put("index.auto_expand_replicas", minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                    .build();
            CreateIndexRequest indexRequest = new CreateIndexRequest(Detector.DETECTORS_INDEX)
                    .mapping(detectorMappings())
                    .settings(indexSettings);
            client.indices().create(indexRequest, actionListener);
        }
    }

    public boolean detectorIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(Detector.DETECTORS_INDEX);
    }

    public ClusterIndexHealth detectorIndexHealth() {
        ClusterIndexHealth indexHealth = null;

        if (detectorIndexExists()) {
            IndexRoutingTable indexRoutingTable = clusterService.state().routingTable().index(Detector.DETECTORS_INDEX);
            IndexMetadata indexMetadata = clusterService.state().metadata().index(Detector.DETECTORS_INDEX);

            indexHealth = new ClusterIndexHealth(indexMetadata, indexRoutingTable);
        }
        return indexHealth;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }
}