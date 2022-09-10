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
import org.opensearch.cluster.health.ClusterIndexHealth;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

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
            CreateIndexRequest indexRequest = new CreateIndexRequest(Detector.DETECTORS_INDEX)
                    .mapping(detectorMappings())
                    .settings(Settings.builder().put("index.hidden", true).build());
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