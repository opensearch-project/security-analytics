/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
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
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.ListCorrelationsAction;
import org.opensearch.securityanalytics.action.ListCorrelationsRequest;
import org.opensearch.securityanalytics.action.ListCorrelationsResponse;
import org.opensearch.securityanalytics.model.CorrelatedFinding;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class TransportListCorrelationAction extends HandledTransportAction<ListCorrelationsRequest, ListCorrelationsResponse> {

    private static final Logger log = LogManager.getLogger(TransportListCorrelationAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    @Inject
    public TransportListCorrelationAction(TransportService transportService,
                                          Client client,
                                          NamedXContentRegistry xContentRegistry,
                                          ClusterService clusterService,
                                          Settings settings,
                                          ActionFilters actionFilters) {
        super(ListCorrelationsAction.NAME, transportService, actionFilters, ListCorrelationsRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.client.threadPool();
    }

    @Override
    protected void doExecute(Task task, ListCorrelationsRequest request, ActionListener<ListCorrelationsResponse> actionListener) {
        AsyncListCorrelationAction asyncAction = new AsyncListCorrelationAction(task, request, actionListener);
        asyncAction.start();
    }

    class AsyncListCorrelationAction {
        private ListCorrelationsRequest request;
        private ActionListener<ListCorrelationsResponse> listener;

        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncListCorrelationAction(Task task, ListCorrelationsRequest request, ActionListener<ListCorrelationsResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response =new AtomicReference<>();
        }

        void start() {
            Long startTimestamp = request.getStartTimestamp();
            Long endTimestamp = request.getEndTimestamp();

            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                    .mustNot(QueryBuilders.matchQuery(
                            "finding1", ""
                    )).mustNot(QueryBuilders.matchQuery(
                            "finding2", ""
                    )).filter(QueryBuilders.rangeQuery("timestamp")
                            .gte(startTimestamp)
                            .lte(endTimestamp));
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
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }

                    List<CorrelatedFinding> correlatedFindings = new ArrayList<>();
                    Iterator<SearchHit> hits = response.getHits().iterator();
                    while (hits.hasNext()) {
                        SearchHit hit = hits.next();
                        Map<String, Object> source = hit.getSourceAsMap();

                        CorrelatedFinding correlatedFinding = new CorrelatedFinding(
                                source.get("finding1").toString(),
                                source.get("logType").toString().split("-")[0],
                                source.get("finding2").toString(),
                                source.get("logType").toString().split("-")[1]);
                        correlatedFindings.add(correlatedFinding);
                    }
                    onOperation(new ListCorrelationsResponse(correlatedFindings));
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void onOperation(ListCorrelationsResponse response) {
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

        private void finishHim(ListCorrelationsResponse response, Exception t) {
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