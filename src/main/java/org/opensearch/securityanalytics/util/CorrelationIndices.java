/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

public class CorrelationIndices {

    private static final Logger log = LogManager.getLogger(CorrelationIndices.class);

    public static final String CORRELATION_METADATA_INDEX = ".opensearch-sap-correlation-metadata";
    public static final String CORRELATION_HISTORY_INDEX_PATTERN = "<.opensearch-sap-correlation-history-{now/d}-1>";

    public static final String CORRELATION_HISTORY_INDEX_PATTERN_REGEXP = ".opensearch-sap-correlation-history*";

    public static final String CORRELATION_HISTORY_WRITE_INDEX = ".opensearch-sap-correlation-history-write";
    public static final long FIXED_HISTORICAL_INTERVAL = 24L * 60L * 60L * 20L * 1000L;

    private final Client client;

    private final ClusterService clusterService;

    public CorrelationIndices(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public static String correlationMappings() throws IOException {
        return new String(Objects.requireNonNull(CorrelationIndices.class.getClassLoader().getResourceAsStream("mappings/correlation.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initCorrelationIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!correlationIndexExists()) {
            CreateIndexRequest indexRequest = new CreateIndexRequest(CORRELATION_HISTORY_INDEX_PATTERN)
                    .mapping(correlationMappings())
                    .settings(Settings.builder().put("index.hidden", true).put("index.correlation", true).build());
            indexRequest.alias(new Alias(CORRELATION_HISTORY_WRITE_INDEX));
            client.admin().indices().create(indexRequest, actionListener);
        } else {
            actionListener.onResponse(new CreateIndexResponse(true, true, CORRELATION_HISTORY_INDEX_PATTERN));
        }
    }

    public void initCorrelationMetadataIndex(ActionListener<CreateIndexResponse> actionListener) throws IOException {
        if (!correlationMetadataIndexExists()) {
            CreateIndexRequest indexRequest = new CreateIndexRequest(CORRELATION_METADATA_INDEX)
                    .mapping(correlationMappings())
                    .settings(Settings.builder().put("index.hidden", true).put("index.correlation", true).build());
            client.admin().indices().create(indexRequest, actionListener);
        } else {
            actionListener.onResponse(new CreateIndexResponse(true, true, CORRELATION_METADATA_INDEX));
        }
    }

    public boolean correlationIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.metadata().hasAlias(CORRELATION_HISTORY_WRITE_INDEX);
    }

    public boolean correlationMetadataIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.metadata().hasIndex(CORRELATION_METADATA_INDEX);
    }

    public void setupCorrelationIndex(TimeValue indexTimeout, Long setupTimestamp, ActionListener<BulkResponse> listener) throws IOException {
        try {
            long currentTimestamp = System.currentTimeMillis();
            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
            builder.field("root", true);
            builder.field("counter", 0L);
            builder.field("finding1", "");
            builder.field("finding2", "");
            builder.field("logType", "");
            builder.field("timestamp", currentTimestamp);
            builder.field("scoreTimestamp", 0L);
            builder.endObject();

            IndexRequest indexRequest = new IndexRequest(CORRELATION_METADATA_INDEX)
                    .source(builder)
                    .timeout(indexTimeout);

            XContentBuilder scoreBuilder = XContentFactory.jsonBuilder().startObject();
            scoreBuilder.field("scoreTimestamp", setupTimestamp);
            scoreBuilder.field("root", false);
            scoreBuilder.endObject();

            IndexRequest scoreIndexRequest = new IndexRequest(CORRELATION_METADATA_INDEX)
                    .source(scoreBuilder)
                    .timeout(indexTimeout);

            BulkRequest bulkRequest = new BulkRequest();
            bulkRequest.add(indexRequest);
            bulkRequest.add(scoreIndexRequest);
            bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);


            client.bulk(bulkRequest, listener);
        } catch (IOException ex) {
            log.error(ex);
            throw ex;
        }
    }
}