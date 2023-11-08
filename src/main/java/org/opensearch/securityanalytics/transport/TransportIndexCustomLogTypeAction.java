/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.MatchQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.metrics.Max;
import org.opensearch.search.aggregations.metrics.MaxAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeAction;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CustomLogTypeIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class TransportIndexCustomLogTypeAction extends HandledTransportAction<IndexCustomLogTypeRequest, IndexCustomLogTypeResponse> implements SecureTransportAction {

    private final Client client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final Settings settings;

    private final DetectorIndices detectorIndices;

    private final CustomLogTypeIndices customLogTypeIndices;

    private final LogTypeService logTypeService;

    private volatile Boolean filterByEnabled;

    private volatile TimeValue indexTimeout;

    @Inject
    public TransportIndexCustomLogTypeAction(TransportService transportService,
                                             Client client,
                                             ActionFilters actionFilters,
                                             ClusterService clusterService,
                                             DetectorIndices detectorIndices,
                                             CustomLogTypeIndices customLogTypeIndices,
                                             LogTypeService logTypeService,
                                             Settings settings,
                                             ThreadPool threadPool) {
        super(IndexCustomLogTypeAction.NAME, transportService, actionFilters, IndexCustomLogTypeRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.detectorIndices = detectorIndices;
        this.customLogTypeIndices = customLogTypeIndices;
        this.logTypeService = logTypeService;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.INDEX_TIMEOUT, this::setIndexTimeout);
    }

    @Override
    protected void doExecute(Task task, IndexCustomLogTypeRequest request, ActionListener<IndexCustomLogTypeResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }
        AsyncIndexCustomLogTypeAction asyncAction = new AsyncIndexCustomLogTypeAction(task, request, listener);
        asyncAction.start();
    }

    public void onCreateMappingsResponse(CreateIndexResponse response) {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Created %s with mappings.", LogTypeService.LOG_TYPE_INDEX));
            IndexUtils.customLogTypeIndexUpdated();
        } else {
            log.error(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged.", LogTypeService.LOG_TYPE_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", LogTypeService.LOG_TYPE_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void onUpdateMappingsResponse(AcknowledgedResponse response) {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Updated  %s with mappings.", LogTypeService.LOG_TYPE_INDEX));
            IndexUtils.customLogTypeIndexUpdated();
        } else {
            log.error(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", LogTypeService.LOG_TYPE_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", LogTypeService.LOG_TYPE_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    class AsyncIndexCustomLogTypeAction {
        private final IndexCustomLogTypeRequest request;

        private final ActionListener<IndexCustomLogTypeResponse> listener;

        private final AtomicReference<Object> response;

        private final AtomicBoolean counter = new AtomicBoolean();

        private final Task task;

        AsyncIndexCustomLogTypeAction(Task task, IndexCustomLogTypeRequest request, ActionListener<IndexCustomLogTypeResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            TransportIndexCustomLogTypeAction.this.threadPool.getThreadContext().stashContext();
            try {
                if (!customLogTypeIndices.customLogTypeIndexExists()) {
                    customLogTypeIndices.initCustomLogTypeIndex(new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            try {
                                onCreateMappingsResponse(response);
                                prepareCustomLogTypeIndexing();
                            } catch (IOException ex) {
                                onFailures(ex);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                } else if (!IndexUtils.customLogTypeIndexUpdated) {
                    IndexUtils.updateIndexMapping(LogTypeService.LOG_TYPE_INDEX,
                            CustomLogTypeIndices.customLogTypeMappings(),
                            clusterService.state(),
                            client.admin().indices(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    try {
                                        onUpdateMappingsResponse(response);
                                        prepareCustomLogTypeIndexing();
                                    } catch (IOException ex) {
                                        onFailures(ex);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            }, false
                    );
                } else {
                    prepareCustomLogTypeIndexing();
                }
            } catch (IOException ex) {
                onFailures(ex);
            }
        }

        private void prepareCustomLogTypeIndexing() throws IOException {
            String logTypeId = request.getLogTypeId();
            String source = request.getCustomLogType().getSource();
            if (source.equals("Sigma")) {
                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated because source is sigma", logTypeId), RestStatus.BAD_REQUEST));
            }

            if (request.getMethod() == RestRequest.Method.PUT) {
                searchLogTypes(logTypeId, new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Search request timed out. Log Type with id %s cannot be updated", logTypeId), RestStatus.REQUEST_TIMEOUT));
                            return;
                        }

                        if (response.getHits().getTotalHits().value != 1) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated", logTypeId), RestStatus.INTERNAL_SERVER_ERROR));
                            return;
                        }

                        try {
                            Map<String, Object> sourceMap = response.getHits().getHits()[0].getSourceAsMap();
                            CustomLogType existingLogType = new CustomLogType(sourceMap);
                            existingLogType.setId(request.getCustomLogType().getId());
                            existingLogType.setVersion(request.getCustomLogType().getVersion());

                            if (existingLogType.getSource().equals("Sigma")) {
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated because source is sigma", logTypeId), RestStatus.BAD_REQUEST));
                            }
                            if (!existingLogType.getName().equals(request.getCustomLogType().getName())) {

                                if (detectorIndices.detectorIndexExists()) {
                                    searchDetectors(existingLogType.getName(), new ActionListener<>() {
                                        @Override
                                        public void onResponse(SearchResponse response) {
                                            if (response.isTimedOut()) {
                                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Search request timed out. Log Type with id %s cannot be updated", logTypeId), RestStatus.REQUEST_TIMEOUT));
                                                return;
                                            }

                                            if (response.getHits().getTotalHits().value > 0) {
                                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Name of Log Type with id %s cannot be updated because active detectors exist", logTypeId), RestStatus.BAD_REQUEST));
                                                return;
                                            }

                                            searchRules(existingLogType.getName(), new ActionListener<>() {
                                                @Override
                                                public void onResponse(SearchResponse response) {
                                                    if (response.isTimedOut()) {
                                                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Search request timed out. Log Type with id %s cannot be updated", logTypeId), RestStatus.REQUEST_TIMEOUT));
                                                        return;
                                                    }

                                                    if (response.getHits().getTotalHits().value > 0) {
                                                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Name of Log Type with id %s cannot be updated because active rules exist", logTypeId), RestStatus.BAD_REQUEST));
                                                        return;
                                                    }

                                                    try {
                                                        request.getCustomLogType().setTags(existingLogType.getTags());
                                                        IndexRequest indexRequest = new IndexRequest(LogTypeService.LOG_TYPE_INDEX)
                                                                .setRefreshPolicy(request.getRefreshPolicy())
                                                                .source(request.getCustomLogType().toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                                                .id(request.getLogTypeId())
                                                                .timeout(indexTimeout);

                                                        client.index(indexRequest, new ActionListener<>() {
                                                            @Override
                                                            public void onResponse(IndexResponse response) {
                                                                if (response.status() != RestStatus.OK) {
                                                                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated", logTypeId), RestStatus.INTERNAL_SERVER_ERROR));
                                                                }
                                                                onOperation(response, request.getCustomLogType());
                                                            }

                                                            @Override
                                                            public void onFailure(Exception e) {
                                                                onFailures(e);
                                                            }
                                                        });
                                                    } catch (IOException e) {
                                                        onFailures(e);
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
                                } else {
                                    request.getCustomLogType().setTags(existingLogType.getTags());
                                    IndexRequest indexRequest = new IndexRequest(LogTypeService.LOG_TYPE_INDEX)
                                            .setRefreshPolicy(request.getRefreshPolicy())
                                            .source(request.getCustomLogType().toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                            .id(request.getLogTypeId())
                                            .timeout(indexTimeout);

                                    client.index(indexRequest, new ActionListener<>() {
                                        @Override
                                        public void onResponse(IndexResponse response) {
                                            if (response.status() != RestStatus.OK) {
                                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated", logTypeId), RestStatus.INTERNAL_SERVER_ERROR));
                                            }

                                            request.getCustomLogType().setId(response.getId());
                                            onOperation(response, request.getCustomLogType());
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            onFailures(e);
                                        }
                                    });
                                }
                            } else {
                                request.getCustomLogType().setTags(existingLogType.getTags());
                                IndexRequest indexRequest = new IndexRequest(LogTypeService.LOG_TYPE_INDEX)
                                        .setRefreshPolicy(request.getRefreshPolicy())
                                        .source(request.getCustomLogType().toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                        .id(request.getLogTypeId())
                                        .timeout(indexTimeout);

                                client.index(indexRequest, new ActionListener<>() {
                                    @Override
                                    public void onResponse(IndexResponse response) {
                                        if (response.status() != RestStatus.OK) {
                                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated", logTypeId), RestStatus.INTERNAL_SERVER_ERROR));
                                        }

                                        request.getCustomLogType().setId(response.getId());
                                        onOperation(response, request.getCustomLogType());
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        onFailures(e);
                                    }
                                });
                            }
                        } catch (IOException e) {
                            onFailures(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                logTypeService.ensureConfigIndexIsInitialized(new ActionListener<>() {
                    @Override
                    public void onResponse(Void unused) {
                        MatchQueryBuilder queryBuilder = QueryBuilders.matchQuery("name", request.getCustomLogType().getName());
                        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                        searchSourceBuilder.query(queryBuilder);
                        SearchRequest searchRequest = new SearchRequest();
                        searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
                        searchRequest.source(searchSourceBuilder);

                        client.search(searchRequest, new ActionListener<>() {
                            @Override
                            public void onResponse(SearchResponse response) {
                                if (response.isTimedOut()) {
                                    onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                    return;
                                }

                                long noOfHits = response.getHits().getTotalHits().value;
                                if (noOfHits > 0) {
                                    onFailures(new OpenSearchStatusException(String.format(Locale.ROOT, "Log Type with name %s already exists", request.getCustomLogType().getName()), RestStatus.INTERNAL_SERVER_ERROR));
                                    return;
                                }
                                MaxAggregationBuilder queryBuilder = AggregationBuilders.max("agg").field("tags.correlation_id");
                                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                                searchSourceBuilder.aggregation(queryBuilder);
                                SearchRequest searchRequest = new SearchRequest();
                                searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
                                searchRequest.source(searchSourceBuilder);

                                client.search(searchRequest, new ActionListener<>() {
                                    @Override
                                    public void onResponse(SearchResponse response) {
                                        if (response.isTimedOut()) {
                                            onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                            return;
                                        }

                                        try {
                                            Max agg = response.getAggregations().get("agg");
                                            int value = Double.valueOf(agg.getValue()).intValue();
                                            request.getCustomLogType().setTags(Map.of("correlation_id", value + 1));
                                            IndexRequest indexRequest = new IndexRequest(LogTypeService.LOG_TYPE_INDEX)
                                                    .setRefreshPolicy(request.getRefreshPolicy())
                                                    .source(request.getCustomLogType().toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                                    .timeout(indexTimeout);

                                            client.index(indexRequest, new ActionListener<>() {
                                                @Override
                                                public void onResponse(IndexResponse response) {
                                                    if (response.status() != RestStatus.CREATED) {
                                                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be updated", logTypeId), RestStatus.INTERNAL_SERVER_ERROR));
                                                    }
                                                    request.getCustomLogType().setId(response.getId());
                                                    onOperation(response, request.getCustomLogType());
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    onFailures(e);
                                                }
                                            });
                                        } catch (IOException ex) {
                                            onFailures(ex);
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
                });
            }
        }

        private void searchLogTypes(String logTypeId, ActionListener<SearchResponse> listener) {
            QueryBuilder queryBuilder = QueryBuilders.matchQuery("_id", logTypeId);
            SearchRequest searchRequest = new SearchRequest(LogTypeService.LOG_TYPE_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(1));
            client.search(searchRequest, listener);
        }

        private void searchDetectors(String logTypeName, ActionListener<SearchResponse> listener) {
            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery("detector",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery("detector.detector_type", logTypeName)
                            ), ScoreMode.Avg);

            SearchRequest searchRequest = new SearchRequest(Detector.DETECTORS_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(0));

            client.search(searchRequest, listener);
        }

        private void searchRules(String logTypeName, ActionListener<SearchResponse> listener) {
            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery("rule",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery("rule.category", logTypeName)
                            ), ScoreMode.Avg);

            SearchRequest searchRequest = new SearchRequest(Rule.CUSTOM_RULES_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(0));

            client.search(searchRequest, listener);
        }

        private void onOperation(IndexResponse response, CustomLogType logType) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(logType);
            }
        }

        private void onFailures(Exception... t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(CustomLogType logType, Exception... t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null && t.length > 0) {
                    if (t.length > 1) {
                        throw SecurityAnalyticsException.wrap(Arrays.asList(t));
                    } else {
                        throw SecurityAnalyticsException.wrap(t[0]);
                    }
                } else {
                    return new IndexCustomLogTypeResponse(logType.getId(), logType.getVersion(), RestStatus.CREATED, logType);
                }
            }));
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

    private void setIndexTimeout(TimeValue indexTimeout) {
        this.indexTimeout = indexTimeout;
    }
}