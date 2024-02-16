/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.Objects;
import java.util.Locale;

    public class ErrorsHistoryIndex {

        private static final Logger log = LogManager.getLogger(ErrorsHistoryIndex.class);

        private final Client client;

        private final ClusterService clusterService;

        private final ThreadPool threadPool;

        private final LogTypeService logTypeService;

        public ErrorsHistoryIndex(LogTypeService logTypeService, Client client, ClusterService clusterService, ThreadPool threadPool) {
            this.client = client;
            this.clusterService = clusterService;
            this.threadPool = threadPool;
            this.logTypeService = logTypeService;
        }

        public static String errorsHistoryIndexMappings() throws IOException {
            return new String(Objects.requireNonNull(RuleIndices.class.getClassLoader().getResourceAsStream("mappings/errorsHistory.json")).readAllBytes(), Charset.defaultCharset());
        }
        public void initErrorsHistoryIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
            Settings errorHistoryIndexSettings = Settings.builder()
                    .put("index.hidden", true)
                    .build();
            CreateIndexRequest indexRequest = new CreateIndexRequest(DetectorMonitorConfig.OPENSEARCH_SAP_ERROR_INDEX)
                    .mapping(errorsHistoryIndexMappings())
                    .settings(errorHistoryIndexSettings);
            client.admin().indices().create(indexRequest, actionListener);
        }

        public void addErrorsToSAPHistoryIndex(IndexDetectorRequest request, String exception, TimeValue indexTimeout, ActionListener<IndexResponse> actionListener) throws IOException {
            Detector detector = request.getDetector();
            String ruleTopic = detector.getDetectorType();
            String indexName = DetectorMonitorConfig.OPENSEARCH_SAP_ERROR_INDEX;
            Instant timestamp = detector.getLastUpdateTime();
            String detectorId = detector.getId();
            String operation = detectorId.isEmpty() ? "CREATE_DETECTOR" : "UPDATE_DETECTOR";
            String user = detector.getUser() == null ? "user" : detector.getUser().getName();

            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
            builder.field("detectorId", detectorId);
            builder.field("exception", exception);
            builder.field("timestamp", timestamp);
            builder.field("logType", ruleTopic);
            builder.field("operation", operation);
            builder.field("user", user);
            builder.endObject();
            IndexRequest indexRequest = new IndexRequest(indexName)
                    .id(UUIDs.base64UUID())
                    .source(builder)
                    .timeout(indexTimeout)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            client.index(indexRequest, actionListener);
        }
        public void onCreateMappingsResponse(CreateIndexResponse response) {
            if (response.isAcknowledged()) {
                log.info(String.format(Locale.getDefault(), "Created %s with mappings.", DetectorMonitorConfig.OPENSEARCH_SAP_ERROR_INDEX));
            } else {
                log.error(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged.", DetectorMonitorConfig.OPENSEARCH_SAP_ERROR_INDEX));
                throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
            }
        }

        public boolean errorHistoryIndexExists() {
            ClusterState clusterState = clusterService.state();
            return clusterState.getRoutingTable().hasIndex(DetectorMonitorConfig.OPENSEARCH_SAP_ERROR_INDEX);
        }
    }
