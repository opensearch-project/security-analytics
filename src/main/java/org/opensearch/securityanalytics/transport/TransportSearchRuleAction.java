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
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.SearchRuleAction;
import org.opensearch.securityanalytics.action.SearchRuleRequest;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class TransportSearchRuleAction extends HandledTransportAction<SearchRuleRequest, SearchResponse> {

    private static final Logger log = LogManager.getLogger(TransportSearchRuleAction.class);

    private final Client client;

    private final RuleIndices ruleIndices;

    private final ThreadPool threadPool;

    private final ClusterService clusterService;

    private final Settings settings;

    private volatile TimeValue indexTimeout;

    @Inject
    public TransportSearchRuleAction(TransportService transportService, Client client, ActionFilters actionFilters, ClusterService clusterService, RuleIndices ruleIndices, Settings settings) {
        super(SearchRuleAction.NAME, transportService, actionFilters, SearchRuleRequest::new);
        this.client = client;
        this.ruleIndices = ruleIndices;
        this.threadPool = ruleIndices.getThreadPool();
        this.clusterService = clusterService;
        this.settings = settings;

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
    }

    @Override
    protected void doExecute(Task task, SearchRuleRequest request, ActionListener<SearchResponse> listener) {
        AsyncSearchRulesAction asyncAction = new AsyncSearchRulesAction(task, request, listener);
        asyncAction.start();
    }

    class AsyncSearchRulesAction {
        private SearchRuleRequest request;

        private final ActionListener<SearchResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncSearchRulesAction(Task task, SearchRuleRequest request, ActionListener<SearchResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            if (request.isPrepackaged()) {
                ruleIndices.initPrepackagedRulesIndex(
                        new ActionListener<>() {
                            @Override
                            public void onResponse(CreateIndexResponse response) {
                                ruleIndices.onCreateMappingsResponse(response, true);
                                ruleIndices.importRules(WriteRequest.RefreshPolicy.IMMEDIATE, indexTimeout,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(BulkResponse response) {
                                                if (!response.hasFailures()) {
                                                    search(request.getSearchRequest());
                                                } else {
                                                    onFailures(new OpenSearchStatusException(response.buildFailureMessage(), RestStatus.INTERNAL_SERVER_ERROR));
                                                }
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
                        },
                        new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                ruleIndices.onUpdateMappingsResponse(response, true);
                                ruleIndices.deleteRules(new ActionListener<>() {
                                    @Override
                                    public void onResponse(BulkByScrollResponse response) {
                                        ruleIndices.importRules(WriteRequest.RefreshPolicy.IMMEDIATE, indexTimeout,
                                                new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(BulkResponse response) {
                                                        if (!response.hasFailures()) {
                                                            search(request.getSearchRequest());
                                                        } else {
                                                            onFailures(new OpenSearchStatusException(response.buildFailureMessage(), RestStatus.INTERNAL_SERVER_ERROR));
                                                        }
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
                        },
                        new ActionListener<>() {
                            @Override
                            public void onResponse(SearchResponse response) {
                                long count = response.getHits().getTotalHits().value;
                                if (count == 0) {
                                    ruleIndices.importRules(WriteRequest.RefreshPolicy.IMMEDIATE, indexTimeout,
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(BulkResponse response) {
                                                    if (!response.hasFailures()) {
                                                        search(request.getSearchRequest());
                                                    } else {
                                                        onFailures(new RuntimeException(response.buildFailureMessage()));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    onFailures(e);
                                                }
                                            });
                                } else {
                                    search(request.getSearchRequest());
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                onFailures(e);
                            }
                        }
                );
            } else {
                if (ruleIndices.ruleIndexExists(false)) {
                    search(request.getSearchRequest());
                } else {
                    onFailures(new IllegalArgumentException("Custom rule index doesnt exist. Please create custom rules first."));
                }
            }
        }

        private void search(SearchRequest request) {
            client.search(request,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            onOperation(response);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
        }

        private void onOperation(SearchResponse response) {
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

        private void finishHim(SearchResponse response, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return response;
                }
            }));
        }
    }
}