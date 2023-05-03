/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.transport.TransportCorrelateFindingAction;
import org.opensearch.securityanalytics.util.CorrelationIndices;

import java.io.IOException;
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

    public void insertCorrelatedFindings(String detectorType, Finding finding, String logType, List<String> correlatedFindings, float timestampFeature, List<String> correlationRules) {
        long findingTimestamp = finding.getTimestamp().toEpochMilli();
        MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery(
                "root", true
        );
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(queryBuilder);
        searchSourceBuilder.fetchSource(true);
        searchSourceBuilder.size(1);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
        searchRequest.source(searchSourceBuilder);

        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse response) {
                if (response.isTimedOut()) {
                    correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
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
                    SearchRequest searchRequest = new SearchRequest();
                    searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                    searchRequest.source(searchSourceBuilder);

                    mSearchRequest.add(searchRequest);
                }

                client.multiSearch(mSearchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(MultiSearchResponse items) {
                        MultiSearchResponse.Item[] responses = items.getResponses();
                        BulkRequest bulkRequest = new BulkRequest();
                        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                        long prevCounter = -1L;
                        long totalNeighbors = 0L;
                        for (MultiSearchResponse.Item response: responses) {
                            if (response.isFailure()) {
                                log.info(response.getFailureMessage());
                                continue;
                            }

                            long totalHits = response.getResponse().getHits().getTotalHits().value;
                            totalNeighbors += totalHits;

                            for (int idx = 0; idx < totalHits; ++idx) {
                                SearchHit hit = response.getResponse().getHits().getHits()[idx];
                                Map<String, Object> hitSource = hit.getSourceAsMap();
                                long neighborCounter = Long.parseLong(hitSource.get("counter").toString());
                                String correlatedFinding = hitSource.get("finding1").toString();

                                try {
                                    float[] corrVector = new float[101];
                                    if (counter != prevCounter) {
                                        for (int i = 0; i < 100; ++i) {
                                            corrVector[i] = ((float) counter) - 50.0f;
                                        }
                                        corrVector[Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()] = (float) counter;
                                        corrVector[100] = timestampFeature;

                                        XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                        builder.field("root", false);
                                        builder.field("counter", counter);
                                        builder.field("finding1", finding.getId());
                                        builder.field("finding2", "");
                                        builder.field("logType", Integer.valueOf(Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()).toString());
                                        builder.field("timestamp", findingTimestamp);
                                        builder.field("corr_vector", corrVector);
                                        builder.field("recordType", "finding");
                                        builder.field("scoreTimestamp", 0L);
                                        builder.endObject();

                                        IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                .source(builder)
                                                .timeout(indexTimeout);
                                        bulkRequest.add(indexRequest);
                                    }

                                    corrVector = new float[101];
                                    for (int i = 0; i < 100; ++i) {
                                        corrVector[i] = ((float) counter) - 50.0f;
                                    }
                                    corrVector[Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                                    corrVector[Detector.DetectorType.valueOf(logType.toUpperCase(Locale.ROOT)).getDim()] = (2.0f * ((float) neighborCounter) - 50.0f) / 2.0f;
                                    corrVector[100] = timestampFeature;

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

                                    IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                            .source(corrBuilder)
                                            .timeout(indexTimeout);
                                    bulkRequest.add(indexRequest);
                                } catch (IOException ex) {
                                    correlateFindingAction.onFailures(ex);
                                }
                                prevCounter = counter;
                            }
                        }

                        if (totalNeighbors > 0L) {
                            client.bulk(bulkRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(BulkResponse response) {
                                    if (response.hasFailures()) {
                                        correlateFindingAction.onFailures(new OpenSearchStatusException("Correlation of finding failed", RestStatus.INTERNAL_SERVER_ERROR));
                                    }
                                    correlateFindingAction.onOperation();
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    correlateFindingAction.onFailures(e);
                                }
                            });
                        } else {
                            insertOrphanFindings(detectorType, finding, timestampFeature);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        correlateFindingAction.onFailures(e);
                    }
                });
            }

            @Override
            public void onFailure(Exception e) {
                correlateFindingAction.onFailures(e);
            }
        });
    }

    public void insertOrphanFindings(String detectorType, Finding finding, float timestampFeature) {
        long findingTimestamp = finding.getTimestamp().toEpochMilli();
        MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery(
                "root", true
        );
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(queryBuilder);
        searchSourceBuilder.fetchSource(true);
        searchSourceBuilder.size(1);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
        searchRequest.source(searchSourceBuilder);

        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse response) {
                if (response.isTimedOut()) {
                    correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
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

                        IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                .id(id)
                                .source(builder)
                                .timeout(indexTimeout)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                        client.index(indexRequest, new ActionListener<>() {
                            @Override
                            public void onResponse(IndexResponse response) {
                                if (response.status().equals(RestStatus.OK)) {
                                    try {
                                        float[] corrVector = new float[101];
                                        corrVector[Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()] = 50.0f;
                                        corrVector[100] = timestampFeature;

                                        XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                        builder.field("root", false);
                                        builder.field("counter", 50L);
                                        builder.field("finding1", finding.getId());
                                        builder.field("finding2", "");
                                        builder.field("logType", Integer.valueOf(Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()).toString());
                                        builder.field("timestamp", findingTimestamp);
                                        builder.field("corr_vector", corrVector);
                                        builder.field("recordType", "finding");
                                        builder.field("scoreTimestamp", 0L);
                                        builder.endObject();

                                        IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                .source(builder)
                                                .timeout(indexTimeout)
                                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                        client.index(indexRequest, new ActionListener<>() {
                                            @Override
                                            public void onResponse(IndexResponse response) {
                                                if (response.status().equals(RestStatus.CREATED)) {
                                                    correlateFindingAction.onOperation();
                                                } else {
                                                    correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                }
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                correlateFindingAction.onFailures(e);
                                            }
                                        });
                                    } catch (IOException ex) {
                                        correlateFindingAction.onFailures(ex);
                                    }
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                correlateFindingAction.onFailures(e);
                            }
                        });
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

                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                    .id(id)
                                    .source(builder)
                                    .timeout(indexTimeout)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                            client.index(indexRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(IndexResponse response) {
                                    if (response.status().equals(RestStatus.OK)) {
                                        correlateFindingAction.onOperation();
                                        try {
                                            float[] corrVector = new float[101];
                                            corrVector[Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()] = 50.0f;
                                            corrVector[100] = timestampFeature;

                                            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                            builder.field("root", false);
                                            builder.field("counter", 50L);
                                            builder.field("finding1", finding.getId());
                                            builder.field("finding2", "");
                                            builder.field("logType", Integer.valueOf(Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()).toString());
                                            builder.field("timestamp", findingTimestamp);
                                            builder.field("corr_vector", corrVector);
                                            builder.field("recordType", "finding");
                                            builder.field("scoreTimestamp", 0L);
                                            builder.endObject();

                                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                    .source(builder)
                                                    .timeout(indexTimeout)
                                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                            client.index(indexRequest, new ActionListener<>() {
                                                @Override
                                                public void onResponse(IndexResponse response) {
                                                    if (response.status().equals(RestStatus.CREATED)) {
                                                        correlateFindingAction.onOperation();
                                                    } else {
                                                        correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    correlateFindingAction.onFailures(e);
                                                }
                                            });
                                        } catch (IOException ex) {
                                            correlateFindingAction.onFailures(ex);
                                        }
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    correlateFindingAction.onFailures(e);
                                }
                            });
                        } else {
                            float[] query = new float[101];
                            for (int i = 0; i < 100; ++i) {
                                query[i] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                            }
                            query[100] = timestampFeature;

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
                            SearchRequest searchRequest = new SearchRequest();
                            searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                            searchRequest.source(searchSourceBuilder);

                            client.search(searchRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(SearchResponse response) {
                                    if (response.isTimedOut()) {
                                        correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                                    }

                                    long totalHits = response.getHits().getTotalHits().value;
                                    SearchHit hit = totalHits > 0? response.getHits().getHits()[0]: null;
                                    long existCounter = 0L;

                                    if (hit != null) {
                                        Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                                        existCounter = Long.parseLong(hitSource.get("counter").toString());
                                    }

                                    if (totalHits == 0L || existCounter != ((long) (2.0f * ((float) counter) - 50.0f) / 2.0f)) {
                                        try {
                                            float[] corrVector = new float[101];
                                            for (int i = 0; i < 100; ++i) {
                                                corrVector[i] = ((float) counter) - 50.0f;
                                            }
                                            corrVector[Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()] = (float) counter;
                                            corrVector[100] = timestampFeature;

                                            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                            builder.field("root", false);
                                            builder.field("counter", counter);
                                            builder.field("finding1", finding.getId());
                                            builder.field("finding2", "");
                                            builder.field("logType", Integer.valueOf(Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()).toString());
                                            builder.field("timestamp", findingTimestamp);
                                            builder.field("corr_vector", corrVector);
                                            builder.field("recordType", "finding");
                                            builder.field("scoreTimestamp", 0L);
                                            builder.endObject();

                                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                    .source(builder)
                                                    .timeout(indexTimeout)
                                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                            client.index(indexRequest, new ActionListener<>() {
                                                @Override
                                                public void onResponse(IndexResponse response) {
                                                    if (response.status().equals(RestStatus.CREATED)) {
                                                        correlateFindingAction.onOperation();
                                                    } else {
                                                        correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    correlateFindingAction.onFailures(e);
                                                }
                                            });
                                        } catch (IOException ex) {
                                            correlateFindingAction.onFailures(ex);
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

                                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                    .id(id)
                                                    .source(builder)
                                                    .timeout(indexTimeout)
                                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                            client.index(indexRequest, new ActionListener<>() {
                                                @Override
                                                public void onResponse(IndexResponse response) {
                                                    if (response.status().equals(RestStatus.OK)) {
                                                        try {
                                                            float[] corrVector = new float[101];
                                                            for (int i = 0; i < 100; ++i) {
                                                                corrVector[i] = (float) counter;
                                                            }
                                                            corrVector[Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()] = counter + 50.0f;
                                                            corrVector[100] = timestampFeature;

                                                            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
                                                            builder.field("root", false);
                                                            builder.field("counter", counter + 50L);
                                                            builder.field("finding1", finding.getId());
                                                            builder.field("finding2", "");
                                                            builder.field("logType", Integer.valueOf(Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)).getDim()).toString());
                                                            builder.field("timestamp", findingTimestamp);
                                                            builder.field("corr_vector", corrVector);
                                                            builder.field("recordType", "finding");
                                                            builder.field("scoreTimestamp", 0L);
                                                            builder.endObject();

                                                            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                                                    .source(builder)
                                                                    .timeout(indexTimeout)
                                                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                                                            client.index(indexRequest, new ActionListener<>() {
                                                                @Override
                                                                public void onResponse(IndexResponse response) {
                                                                    if (response.status().equals(RestStatus.CREATED)) {
                                                                        correlateFindingAction.onOperation();
                                                                    } else {
                                                                        correlateFindingAction.onFailures(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                                    }
                                                                }

                                                                @Override
                                                                public void onFailure(Exception e) {
                                                                    correlateFindingAction.onFailures(e);
                                                                }
                                                            });
                                                        } catch (IOException ex) {
                                                            correlateFindingAction.onFailures(ex);
                                                        }
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    correlateFindingAction.onFailures(e);
                                                }
                                            });
                                        } catch (IOException ex) {
                                            correlateFindingAction.onFailures(ex);
                                        }
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    correlateFindingAction.onFailures(e);
                                }
                            });
                        }
                    }
                } catch (IOException ex) {
                    correlateFindingAction.onFailures(ex);
                }
            }

            @Override
            public void onFailure(Exception e) {
                correlateFindingAction.onFailures(e);
            }
        });
    }
}