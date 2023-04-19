/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.search.MultiSearchRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.CorrelatedFindingAction;
import org.opensearch.securityanalytics.action.CorrelatedFindingRequest;
import org.opensearch.securityanalytics.action.CorrelatedFindingResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.FindingWithScore;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class TransportSearchCorrelationAction extends HandledTransportAction<CorrelatedFindingRequest, CorrelatedFindingResponse> {

    private static final Logger log = LogManager.getLogger(TransportSearchCorrelationAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    @Inject
    public TransportSearchCorrelationAction(TransportService transportService,
                                            Client client,
                                            NamedXContentRegistry xContentRegistry,
                                            ClusterService clusterService,
                                            Settings settings,
                                            ActionFilters actionFilters) {
        super(CorrelatedFindingAction.NAME, transportService, actionFilters, CorrelatedFindingRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.client.threadPool();
    }

    @Override
    protected void doExecute(Task task, CorrelatedFindingRequest request, ActionListener<CorrelatedFindingResponse> actionListener) {
        AsyncSearchCorrelationAction searchCorrelationAction = new AsyncSearchCorrelationAction(task, request, actionListener);
        searchCorrelationAction.start();
    }

    class AsyncSearchCorrelationAction {
        private CorrelatedFindingRequest request;
        private ActionListener<CorrelatedFindingResponse> listener;

        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncSearchCorrelationAction(Task task, CorrelatedFindingRequest request, ActionListener<CorrelatedFindingResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response =new AtomicReference<>();
        }

        void start() {
            String findingId = request.getFindingId();
            Detector.DetectorType detectorType = request.getDetectorType();
            long timeWindow = request.getTimeWindow();
            int noOfNearbyFindings = request.getNoOfNearbyFindings();

            MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery(
                    "_id", findingId
            );
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(false);
            searchSourceBuilder.fetchField("timestamp");
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(DetectorMonitorConfig.getAllFindingsIndicesPattern(detectorType.getDetectorType()));
            searchRequest.source(searchSourceBuilder);

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    SearchHit hit = response.getHits().getAt(0);
                    long findingTimestamp = hit.getFields().get("timestamp").<Long>getValue();

                    BoolQueryBuilder scoreQueryBuilder = QueryBuilders.boolQuery()
                            .mustNot(QueryBuilders.termQuery("scoreTimestamp", 0L));
                    SearchSourceBuilder scoreSearchSourceBuilder = new SearchSourceBuilder();
                    scoreSearchSourceBuilder.query(scoreQueryBuilder);
                    scoreSearchSourceBuilder.fetchSource(true);
                    scoreSearchSourceBuilder.size(1);
                    SearchRequest scoreSearchRequest = new SearchRequest();
                    scoreSearchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                    scoreSearchRequest.source(scoreSearchSourceBuilder);

                    client.search(scoreSearchRequest, new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                            long scoreTimestamp = (long) hitSource.get("scoreTimestamp");

                            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                                    .must(QueryBuilders.matchQuery(
                                            "finding1", findingId
                                    )).must(QueryBuilders.matchQuery(
                                            "finding2", ""
                                    ));

                            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                            searchSourceBuilder.query(queryBuilder);
                            searchSourceBuilder.fetchSource(false);
                            searchSourceBuilder.fetchField("counter");
                            searchSourceBuilder.size(1);
                            SearchRequest searchRequest = new SearchRequest();
                            searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                            searchRequest.source(searchSourceBuilder);

                            client.search(searchRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(SearchResponse response) {
                                    MultiSearchRequest mSearchRequest = new MultiSearchRequest();
                                    SearchHit[] hits = response.getHits().getHits();

                                    for (SearchHit hit: hits) {
                                        long counter = hit.getFields().get("counter").<Long>getValue();
                                        float[] query = new float[101];
                                        for (int i = 0; i < 100; ++i) {
                                            query[i] = (2.0f * ((float) counter) - 50.0f) / 2.0f;
                                        }
                                        query[100] = Long.valueOf((findingTimestamp - scoreTimestamp) / 1000L).floatValue();

                                        CorrelationQueryBuilder correlationQueryBuilder = new CorrelationQueryBuilder("corr_vector", query, noOfNearbyFindings, QueryBuilders.boolQuery()
                                                .mustNot(QueryBuilders.matchQuery(
                                                        "finding1", ""
                                                )).mustNot(QueryBuilders.matchQuery(
                                                        "finding2", ""
                                                )).filter(QueryBuilders.rangeQuery("timestamp")
                                                        .gte(findingTimestamp - timeWindow)
                                                        .lte(findingTimestamp + timeWindow)));

                                        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                                        searchSourceBuilder.query(correlationQueryBuilder);
                                        searchSourceBuilder.fetchSource(true);
                                        searchSourceBuilder.size(noOfNearbyFindings);
                                        SearchRequest searchRequest = new SearchRequest();
                                        searchRequest.indices(CorrelationIndices.CORRELATION_INDEX);
                                        searchRequest.source(searchSourceBuilder);

                                        mSearchRequest.add(searchRequest);
                                    }

                                    client.multiSearch(mSearchRequest, new ActionListener<>() {
                                        @Override
                                        public void onResponse(MultiSearchResponse items) {
                                            MultiSearchResponse.Item[] responses = items.getResponses();
                                            Map<Pair<String, String>, Double> correlatedFindings = new HashMap<>();

                                            for (MultiSearchResponse.Item response : responses) {
                                                if (response.isFailure()) {
                                                    log.info(response.getFailureMessage());
                                                    continue;
                                                }

                                                SearchHit[] hits = response.getResponse().getHits().getHits();
                                                for (SearchHit hit: hits) {
                                                    Map<String, Object> source = hit.getSourceAsMap();
                                                    if (!source.get("finding1").toString().equals(findingId)) {
                                                        Pair<String, String> findingKey1 = Pair.of(source.get("finding1").toString(), source.get("logType").toString().split("-")[0]);

                                                        if (correlatedFindings.containsKey(findingKey1)) {
                                                            correlatedFindings.put(findingKey1, Math.max(correlatedFindings.get(findingKey1), hit.getScore()));
                                                        } else {
                                                            correlatedFindings.put(findingKey1, (double) hit.getScore());
                                                        }
                                                    }
                                                    if (!source.get("finding2").toString().equals(findingId)) {
                                                        Pair<String, String> findingKey2 = Pair.of(source.get("finding2").toString(), source.get("logType").toString().split("-")[1]);

                                                        if (correlatedFindings.containsKey(findingKey2)) {
                                                            correlatedFindings.put(findingKey2, Math.max(correlatedFindings.get(findingKey2), hit.getScore()));
                                                        } else {
                                                            correlatedFindings.put(findingKey2, (double) hit.getScore());
                                                        }
                                                    }
                                                }
                                            }

                                            List<FindingWithScore> findingWithScores = new ArrayList<>();
                                            for (Map.Entry<Pair<String, String>, Double> correlatedFinding: correlatedFindings.entrySet()) {
                                                findingWithScores.add(new FindingWithScore(correlatedFinding.getKey().getKey(), correlatedFinding.getKey().getValue(), correlatedFinding.getValue()));
                                            }

                                            onOperation(new CorrelatedFindingResponse(findingWithScores));
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            onFailures(e);
                                        }
                                    });
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });

        }

        private void onOperation(CorrelatedFindingResponse response) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(response, null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(CorrelatedFindingResponse response, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return response;
                }
            }));
        }
    }
}