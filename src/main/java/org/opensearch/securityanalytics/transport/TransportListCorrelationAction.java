/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.ListCorrelationsAction;
import org.opensearch.securityanalytics.action.ListCorrelationsRequest;
import org.opensearch.securityanalytics.action.ListCorrelationsResponse;
import org.opensearch.securityanalytics.model.CorrelatedFinding;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class TransportListCorrelationAction extends HandledTransportAction<ListCorrelationsRequest, ListCorrelationsResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportListCorrelationAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

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
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
    }

    @Override
    protected void doExecute(Task task, ListCorrelationsRequest request, ActionListener<ListCorrelationsResponse> actionListener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
        this.threadPool.getThreadContext().stashContext();

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

        @SuppressWarnings("unchecked")
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
            searchSourceBuilder.size(10000);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN_REGEXP);
            searchRequest.source(searchSourceBuilder);
            searchRequest.preference(Preference.PRIMARY_FIRST.type());

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                    }

                    Map<String, CorrelatedFinding> correlatedFindings = new HashMap<>();
                    Iterator<SearchHit> hits = response.getHits().iterator();
                    while (hits.hasNext()) {
                        SearchHit hit = hits.next();
                        Map<String, Object> source = hit.getSourceAsMap();

                        CorrelatedFinding correlatedFinding = new CorrelatedFinding(
                                source.get("finding1").toString(),
                                source.get("logType").toString().split("-")[0],
                                source.get("finding2").toString(),
                                source.get("logType").toString().split("-")[1],
                                (List<String>) source.get("corrRules"));
                        correlatedFindings.put(source.get("finding1").toString() + ":" + source.get("finding2").toString(), correlatedFinding);
                    }
                    onOperation(new ListCorrelationsResponse(new ArrayList<>(correlatedFindings.values())));
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