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
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.authuser.User;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CustomLogTypeIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportDeleteCustomLogTypeAction extends HandledTransportAction<DeleteCustomLogTypeRequest, DeleteCustomLogTypeResponse> implements SecureTransportAction {

    private final Client client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final Settings settings;

    private final DetectorIndices detectorIndices;

    private final CustomLogTypeIndices customLogTypeIndices;

    private volatile Boolean filterByEnabled;

    private volatile TimeValue indexTimeout;

    @Inject
    public TransportDeleteCustomLogTypeAction(TransportService transportService,
                                              Client client,
                                              ActionFilters actionFilters,
                                              ClusterService clusterService,
                                              DetectorIndices detectorIndices,
                                              CustomLogTypeIndices customLogTypeIndices,
                                              Settings settings,
                                              ThreadPool threadPool) {
        super(DeleteCustomLogTypeAction.NAME, transportService, actionFilters, DeleteCustomLogTypeRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.detectorIndices = detectorIndices;
        this.customLogTypeIndices = customLogTypeIndices;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.INDEX_TIMEOUT, this::setIndexTimeout);
    }

    @Override
    protected void doExecute(Task task, DeleteCustomLogTypeRequest request, ActionListener<DeleteCustomLogTypeResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }
        this.threadPool.getThreadContext().stashContext();
        AsyncDeleteCustomLogTypeAction deleteCustomLogTypeAction = new AsyncDeleteCustomLogTypeAction(task, request, listener);
        deleteCustomLogTypeAction.start();
    }

    class AsyncDeleteCustomLogTypeAction {

        private final DeleteCustomLogTypeRequest request;

        private final ActionListener<DeleteCustomLogTypeResponse> listener;

        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();

        private Task task;

        AsyncDeleteCustomLogTypeAction(
                Task task,
                DeleteCustomLogTypeRequest request,
                ActionListener<DeleteCustomLogTypeResponse> listener
        ) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.response = new AtomicReference<>();
        }

        void start() {
            if (!customLogTypeIndices.customLogTypeIndexExists()) {
                onFailures(new OpenSearchStatusException(
                        String.format(Locale.getDefault(),
                                "Log Type with id %s is not found",
                                request.getLogTypeId()),
                        RestStatus.NOT_FOUND));
                return;
            }
            String logTypeId = request.getLogTypeId();
            GetRequest getRequest = new GetRequest(LogTypeService.LOG_TYPE_INDEX, logTypeId);
            client.get(getRequest, new ActionListener<>() {
                @Override
                public void onResponse(GetResponse response) {
                    if (!response.isExists()) {
                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s is not found", logTypeId), RestStatus.NOT_FOUND));
                        return;
                    }

                    Map<String, Object> sourceMap = response.getSourceAsMap();
                    CustomLogType logType = new CustomLogType(sourceMap);
                    logType.setId(response.getId());
                    logType.setVersion(response.getVersion());

                    onGetResponse(logType);
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s is not found", logTypeId), RestStatus.NOT_FOUND));
                }
            });
        }

        private void onGetResponse(CustomLogType logType) {
            if (logType.getSource().equals("Sigma")) {
                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted because source is sigma", logType.getId()), RestStatus.BAD_REQUEST));
            }

            if (detectorIndices.detectorIndexExists()) {
                searchDetectors(logType.getName(), new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted", logType.getId()), RestStatus.INTERNAL_SERVER_ERROR));
                            return;
                        }

                        if (response.getHits().getTotalHits().value > 0) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted because active detectors exist", logType.getId()), RestStatus.BAD_REQUEST));
                            return;
                        }

                        searchRules(logType.getName(), new ActionListener<>() {
                            @Override
                            public void onResponse(SearchResponse response) {
                                if (response.isTimedOut()) {
                                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted", logType.getId()), RestStatus.INTERNAL_SERVER_ERROR));
                                    return;
                                }

                                if (response.getHits().getTotalHits().value > 0) {
                                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted because active rules exist", logType.getId()), RestStatus.BAD_REQUEST));
                                    return;
                                }

                                DeleteRequest deleteRequest = new DeleteRequest(LogTypeService.LOG_TYPE_INDEX, logType.getId())
                                        .setRefreshPolicy(request.getRefreshPolicy())
                                        .timeout(indexTimeout);

                                client.delete(deleteRequest, new ActionListener<>() {
                                    @Override
                                    public void onResponse(DeleteResponse response) {
                                        if (response.status() != RestStatus.OK) {
                                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted", logType.getId()), RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                        onOperation(response);
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
            } else {
                DeleteRequest deleteRequest = new DeleteRequest(LogTypeService.LOG_TYPE_INDEX, logType.getId())
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .timeout(indexTimeout);

                client.delete(deleteRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(DeleteResponse response) {
                        if (response.status() != RestStatus.OK) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Log Type with id %s cannot be deleted", logType.getId()), RestStatus.INTERNAL_SERVER_ERROR));
                        }
                        onOperation(response);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            }
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

        private void onOperation(DeleteResponse response) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(response.getId(), null);
            }
        }

        private void onFailures(Exception t) {
            log.error(String.format(Locale.ROOT, "Failed to delete detector"));
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(String logTypeId, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    log.error(String.format(Locale.ROOT, "Failed to delete log type %s",logTypeId), t);
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new DeleteCustomLogTypeResponse(logTypeId, NO_VERSION, RestStatus.NO_CONTENT);
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