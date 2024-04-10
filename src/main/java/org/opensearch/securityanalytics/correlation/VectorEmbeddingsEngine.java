/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.transport.TransportCorrelateFindingAction;
import org.opensearch.securityanalytics.util.CorrelationIndices;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class VectorEmbeddingsEngine {

    private final Client client;

    private final TransportCorrelateFindingAction.AsyncCorrelateFindingAction correlateFindingAction;

    private volatile TimeValue indexTimeout;

    private volatile long corrTimeWindow;

    private static final Logger log = LogManager.getLogger(VectorEmbeddingsEngine.class);

    public VectorEmbeddingsEngine(Client client, TimeValue indexTimeout, long corrTimeWindow,
                                  TransportCorrelateFindingAction.AsyncCorrelateFindingAction correlateFindingAction) {
        this.client = client;
        this.indexTimeout = indexTimeout;
        this.corrTimeWindow = corrTimeWindow;
        this.correlateFindingAction = correlateFindingAction;
    }

    public void insertCorrelatedFindings(String detectorType, Finding finding, String logType, List<String> correlatedFindings, float timestampFeature, List<String> correlationRules, Map<String, CustomLogType> logTypes) {
        SearchRequest searchRequest = getSearchMetadataIndexRequest(detectorType, finding, logTypes);
        Map<String, Object> tags = logTypes.get(detectorType).getTags();
        String correlationId = tags.get("correlation_id").toString();

        long findingTimestamp = finding.getTimestamp().toEpochMilli();
        client.search(searchRequest, ActionListener.wrap(response -> {
            if (response.isTimedOut()) {
                onFailure(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
            }

            if (response.getHits().getHits().length == 0) {
                onFailure(
                        new ResourceNotFoundException("Failed to find hits in metadata index for finding id {}", finding.getId()));
            }

            Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
            long counter = Long.parseLong(hitSource.get("counter").toString());

            MultiSearchRequest mSearchRequest = new MultiSearchRequest();

            for (String correlatedFinding: correlatedFindings) {
                BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                        .must(QueryBuilders.matchQuery(
                                "finding1", correlatedFinding
                        )).must(QueryBuilders.matchQuery(
                                "finding2", ""
                        ))/*.must(QueryBuilders.matchQuery(
                                "counter", counter
                        ))*/;
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(true);
                searchSourceBuilder.size(10000);
                SearchRequest request = new SearchRequest();
                request.indices(CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN_REGEXP);
                request.source(searchSourceBuilder);
                request.preference(Preference.PRIMARY_FIRST.type());
                request.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

                mSearchRequest.add(request);
            }

            client.multiSearch(mSearchRequest, ActionListener.wrap(items -> {
                MultiSearchResponse.Item[] responses = items.getResponses();
                BulkRequest bulkRequest = new BulkRequest();
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                long prevCounter = -1L;
                long totalNeighbors = 0L;
                for (MultiSearchResponse.Item item: responses) {
                    if (item.isFailure()) {
                        log.info(item.getFailureMessage());
                        continue;
                    }

                    long totalHits = item.getResponse().getHits().getHits().length;
                    totalNeighbors += totalHits;

                    for (int idx = 0; idx < totalHits; ++idx) {
                        SearchHit hit = item.getResponse().getHits().getHits()[idx];
                        Map<String, Object> sourceAsMap = hit.getSourceAsMap();
                        long neighborCounter = Long.parseLong(sourceAsMap.get("counter").toString());
                        String correlatedFinding = sourceAsMap.get("finding1").toString();

                        try {
                            float[] corrVector = new float[3];
                            if (counter != prevCounter) {
                                for (int i = 0; i < 2; ++i) {
                                    corrVector[i] = ((float) counter) - 50.0f;
                                }

                                corrVector[0] = (float) counter;
                                corrVector[2] = timestampFeature;

                                XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                builder.field("root", false);
                                builder.field("counter", counter);
                                builder.field("finding1", finding.getId());
                                builder.field("finding2", "");
                                builder.field("logType", correlationId);
                                builder.field("timestamp", findingTimestamp);
                                builder.field("corr_vector", corrVector);
                                builder.field("recordType", "finding");
                                builder.field("scoreTimestamp", 0L);
                                builder.endObject();

                                IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX)
                                        .source(builder)
                                        .timeout(indexTimeout);
                                bulkRequest.add(indexRequest);
                            }

                            corrVector = new float[3];
                            for (int i = 0; i < 2; ++i) {
                                corrVector[i] = ((float) counter) - 50.0f;
                            }
                            corrVector[0] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                            corrVector[1] = (2.0f * ((float) neighborCounter) - 50.0f) / 2.0f;
                            corrVector[2] = timestampFeature;

                            XContentBuilder corrBuilder = XContentFactory.jsonBuilder().startObject();
                            corrBuilder.field("root", false);
                            corrBuilder.field("counter", (long) ((2.0f * ((float) counter) - 50.0f) / 2.0f));
                            corrBuilder.field("finding1", finding.getId());
                            corrBuilder.field("finding2", correlatedFinding);
                            corrBuilder.field("logType", String.format(Locale.ROOT, "%s-%s", detectorType, logType));
                            corrBuilder.field("timestamp", findingTimestamp);
                            corrBuilder.field("corr_vector", corrVector);
                            corrBuilder.field("recordType", "finding-finding");
                            corrBuilder.field("scoreTimestamp", 0L);
                            corrBuilder.field("corrRules", correlationRules);
                            corrBuilder.endObject();

                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX)
                                    .source(corrBuilder)
                                    .timeout(indexTimeout);
                            bulkRequest.add(indexRequest);
                        } catch (Exception ex) {
                            onFailure(ex);
                        }
                        prevCounter = counter;
                    }
                }

                if (totalNeighbors > 0L) {
                    client.bulk(bulkRequest, ActionListener.wrap( bulkResponse -> {
                        if (bulkResponse.hasFailures()) {
                            onFailure(new OpenSearchStatusException("Correlation of finding failed", RestStatus.INTERNAL_SERVER_ERROR));
                        }
                        correlateFindingAction.onOperation();
                    }, this::onFailure));
                } else {
                    insertOrphanFindings(detectorType, finding, timestampFeature, logTypes);
                }
            }, this::onFailure));
        }, this::onFailure));
    }

    public void insertOrphanFindings(String detectorType, Finding finding, float timestampFeature, Map<String, CustomLogType> logTypes) {
        if (logTypes.get(detectorType) == null ) {
            log.debug("Missing detector type {} in the log types index for finding id {}. Keys in the index: {}",
                    detectorType, finding.getId(), Arrays.toString(logTypes.keySet().toArray()));
            onFailure(new OpenSearchStatusException("insertOrphanFindings null log types for detector type: " + detectorType, RestStatus.INTERNAL_SERVER_ERROR));
        }

        SearchRequest searchRequest = getSearchMetadataIndexRequest(detectorType, finding, logTypes);
        Map<String, Object> tags = logTypes.get(detectorType).getTags();
        String correlationId = tags.get("correlation_id").toString();
        long findingTimestamp = finding.getTimestamp().toEpochMilli();

        client.search(searchRequest, ActionListener.wrap(response -> {
            if (response.isTimedOut()) {
                onFailure(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
            }

            try {
                Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                String id = response.getHits().getHits()[0].getId();
                long counter = Long.parseLong(hitSource.get("counter").toString());
                long timestamp = Long.parseLong(hitSource.get("timestamp").toString());
                if (counter == 0L) {
                    XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                    builder.field("root", true);
                    builder.field("counter", 50L);
                    builder.field("finding1", "");
                    builder.field("finding2", "");
                    builder.field("logType", "");
                    builder.field("timestamp", findingTimestamp);
                    builder.field("scoreTimestamp", 0L);
                    builder.endObject();

                    IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_METADATA_INDEX)
                            .id(id)
                            .source(builder)
                            .timeout(indexTimeout)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                    client.index(indexRequest, ActionListener.wrap(indexResponse -> {
                        if (indexResponse.status().equals(RestStatus.OK)) {
                            try {
                                float[] corrVector = new float[3];
                                corrVector[0] = 50.0f;
                                corrVector[2] = timestampFeature;

                                XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject();
                                xContentBuilder.field("root", false);
                                xContentBuilder.field("counter", 50L);
                                xContentBuilder.field("finding1", finding.getId());
                                xContentBuilder.field("finding2", "");
                                xContentBuilder.field("logType", correlationId);
                                xContentBuilder.field("timestamp", findingTimestamp);
                                xContentBuilder.field("corr_vector", corrVector);
                                xContentBuilder.field("recordType", "finding");
                                xContentBuilder.field("scoreTimestamp", 0L);
                                xContentBuilder.endObject();

                                indexCorrelatedFindings(xContentBuilder);
                            } catch (Exception ex) {
                                onFailure(ex);
                            }
                        } else {
                            onFailure(new OpenSearchStatusException("Indexing failed with response {} ",
                                    indexResponse.status(), indexResponse.toString()));
                        }
                    }, this::onFailure));
                } else {
                    if (findingTimestamp - timestamp > corrTimeWindow) {
                        XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                        builder.field("root", true);
                        builder.field("counter", 50L);
                        builder.field("finding1", "");
                        builder.field("finding2", "");
                        builder.field("logType", "");
                        builder.field("timestamp", findingTimestamp);
                        builder.field("scoreTimestamp", 0L);
                        builder.endObject();

                        IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_METADATA_INDEX)
                                .id(id)
                                .source(builder)
                                .timeout(indexTimeout)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                        client.index(indexRequest, ActionListener.wrap(indexResponse -> {
                            if (indexResponse.status().equals(RestStatus.OK)) {
                                correlateFindingAction.onOperation();
                                try {
                                    float[] corrVector = new float[3];
                                    corrVector[0] = 50.0f;
                                    corrVector[2] = timestampFeature;

                                    XContentBuilder contentBuilder = XContentFactory.jsonBuilder().startObject();
                                    contentBuilder.field("root", false);
                                    contentBuilder.field("counter", 50L);
                                    contentBuilder.field("finding1", finding.getId());
                                    contentBuilder.field("finding2", "");
                                    contentBuilder.field("logType", Integer.valueOf(logTypes.get(detectorType).getTags().get("correlation_id").toString()).toString());
                                    contentBuilder.field("timestamp", findingTimestamp);
                                    contentBuilder.field("corr_vector", corrVector);
                                    contentBuilder.field("recordType", "finding");
                                    contentBuilder.field("scoreTimestamp", 0L);
                                    contentBuilder.endObject();

                                    indexCorrelatedFindings(contentBuilder);
                                } catch (Exception ex) {
                                    onFailure(ex);
                                }
                            } else {
                                onFailure(new OpenSearchStatusException("Indexing failed with response {} ",
                                        indexResponse.status(), indexResponse.toString()));
                            }
                        }, this::onFailure));
                    } else {
                        float[] query = new float[3];
                        for (int i = 0; i < 2; ++i) {
                            query[i] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                        }
                        query[2] = timestampFeature;

                        CorrelationQueryBuilder correlationQueryBuilder = new CorrelationQueryBuilder("corr_vector", query, 100, QueryBuilders.boolQuery()
                                .mustNot(QueryBuilders.matchQuery(
                                        "finding1", ""
                                )).mustNot(QueryBuilders.matchQuery(
                                        "finding2", ""
                                )).filter(QueryBuilders.rangeQuery("timestamp")
                                        .gte(findingTimestamp - corrTimeWindow)
                                        .lte(findingTimestamp + corrTimeWindow)));
                        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                        searchSourceBuilder.query(correlationQueryBuilder);
                        searchSourceBuilder.fetchSource(true);
                        searchSourceBuilder.size(1);
                        SearchRequest request = new SearchRequest();
                        request.indices(CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN_REGEXP);
                        request.source(searchSourceBuilder);
                        request.preference(Preference.PRIMARY_FIRST.type());
                        request.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

                        client.search(request, ActionListener.wrap(searchResponse -> {
                            if (searchResponse.isTimedOut()) {
                                onFailure(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                            }

                            long totalHits = searchResponse.getHits().getHits().length;
                            SearchHit hit = totalHits > 0? searchResponse.getHits().getHits()[0]: null;
                            long existCounter = 0L;

                            if (hit != null) {
                                Map<String, Object> sourceAsMap = searchResponse.getHits().getHits()[0].getSourceAsMap();
                                existCounter = Long.parseLong(sourceAsMap.get("counter").toString());
                            }

                            if (totalHits == 0L || existCounter != ((long) (2.0f * ((float) counter) - 50.0f) / 2.0f)) {
                                try {
                                    float[] corrVector = new float[3];
                                    for (int i = 0; i < 2; ++i) {
                                        corrVector[i] = ((float) counter) - 50.0f;
                                    }
                                    corrVector[0] = (float) counter;
                                    corrVector[2] = timestampFeature;

                                    XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                    builder.field("root", false);
                                    builder.field("counter", counter);
                                    builder.field("finding1", finding.getId());
                                    builder.field("finding2", "");
                                    builder.field("logType", Integer.valueOf(logTypes.get(detectorType).getTags().get("correlation_id").toString()).toString());
                                    builder.field("timestamp", findingTimestamp);
                                    builder.field("corr_vector", corrVector);
                                    builder.field("recordType", "finding");
                                    builder.field("scoreTimestamp", 0L);
                                    builder.endObject();

                                    indexCorrelatedFindings(builder);
                                } catch (Exception ex) {
                                    onFailure(ex);
                                }
                            } else {
                                try {
                                    XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                    builder.field("root", true);
                                    builder.field("counter", counter + 50L);
                                    builder.field("finding1", "");
                                    builder.field("finding2", "");
                                    builder.field("logType", "");
                                    builder.field("timestamp", findingTimestamp);
                                    builder.field("scoreTimestamp", 0L);
                                    builder.endObject();

                                    IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_METADATA_INDEX)
                                            .id(id)
                                            .source(builder)
                                            .timeout(indexTimeout)
                                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                    client.index(indexRequest, ActionListener.wrap(indexResponse -> {
                                        if (indexResponse.status().equals(RestStatus.OK)) {
                                            try {
                                                float[] corrVector = new float[3];
                                                for (int i = 0; i < 2; ++i) {
                                                    corrVector[i] = (float) counter;
                                                }
                                                corrVector[0] = counter + 50.0f;
                                                corrVector[2] = timestampFeature;

                                                XContentBuilder xContentBuilder = XContentFactory.jsonBuilder().startObject();
                                                xContentBuilder.field("root", false);
                                                xContentBuilder.field("counter", counter + 50L);
                                                xContentBuilder.field("finding1", finding.getId());
                                                xContentBuilder.field("finding2", "");
                                                xContentBuilder.field("logType", Integer.valueOf(logTypes.get(detectorType).getTags().get("correlation_id").toString()).toString());
                                                xContentBuilder.field("timestamp", findingTimestamp);
                                                xContentBuilder.field("corr_vector", corrVector);
                                                xContentBuilder.field("recordType", "finding");
                                                xContentBuilder.field("scoreTimestamp", 0L);
                                                xContentBuilder.endObject();

                                                indexCorrelatedFindings(xContentBuilder);
                                            } catch (Exception ex) {
                                                onFailure(ex);
                                            }
                                        } else {
                                            onFailure(new OpenSearchStatusException("Indexing failed with response {} ",
                                                    indexResponse.status(), indexResponse.toString()));
                                        }
                                    }, this::onFailure));
                                } catch (Exception ex) {
                                    onFailure(ex);
                                }
                            }
                        }, this::onFailure));
                    }
                }
            } catch (Exception ex) {
                onFailure(ex);
            }
        }, this::onFailure));
    }

    private void indexCorrelatedFindings(XContentBuilder builder) {
        IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX)
                .source(builder)
                .timeout(indexTimeout)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        client.index(indexRequest, ActionListener.wrap(response -> {
            if (response.status().equals(RestStatus.CREATED)) {
                correlateFindingAction.onOperation();
            } else {
                onFailure(new OpenSearchStatusException("Indexing failed with response {} ", response.status(), response.toString()));
            }
        }, this::onFailure));
    }

    private SearchRequest getSearchMetadataIndexRequest(String detectorType, Finding finding, Map<String, CustomLogType> logTypes) {
        if (logTypes.get(detectorType) == null) {
            throw new OpenSearchStatusException("LogTypes Index is missing the detector type", RestStatus.INTERNAL_SERVER_ERROR);
        }

        Map<String, Object> tags = logTypes.get(detectorType).getTags();
        MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery(
                "root", true
        );
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(queryBuilder);
        searchSourceBuilder.fetchSource(true);
        searchSourceBuilder.size(1);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(CorrelationIndices.CORRELATION_METADATA_INDEX);
        searchRequest.source(searchSourceBuilder);
        searchRequest.preference(Preference.PRIMARY_FIRST.type());
        searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));
        return searchRequest;
    }

    private void onFailure(Exception e) {
        correlateFindingAction.onFailures(e);
    }
}