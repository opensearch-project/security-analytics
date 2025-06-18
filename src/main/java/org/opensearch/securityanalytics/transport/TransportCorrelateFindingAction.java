/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.commons.alerting.action.PublishBatchFindingsRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.commons.alerting.action.PublishFindingsRequest;
import org.opensearch.commons.alerting.action.SubscribeFindingsResponse;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.InputStreamStreamInput;
import org.opensearch.core.common.io.stream.OutputStreamStreamOutput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.correlation.JoinEngine;
import org.opensearch.securityanalytics.correlation.VectorEmbeddingsEngine;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class TransportCorrelateFindingAction extends HandledTransportAction<ActionRequest, SubscribeFindingsResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportCorrelateFindingAction.class);

    private final DetectorIndices detectorIndices;

    private final CorrelationIndices correlationIndices;

    private final CorrelationRuleIndices correlationRuleIndices;

    private final LogTypeService logTypeService;

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private volatile TimeValue indexTimeout;

    private volatile long corrTimeWindow;

    private volatile long setupTimestamp;

    private volatile boolean enableAutoCorrelation;

    private volatile long autoCorrelationTimebox;

    private final CorrelationAlertService correlationAlertService;

    private final NotificationService notificationService;

    @Inject
    public TransportCorrelateFindingAction(TransportService transportService,
                                           Client client,
                                           NamedXContentRegistry xContentRegistry,
                                           DetectorIndices detectorIndices,
                                           CorrelationIndices correlationIndices,
                                           CorrelationRuleIndices correlationRuleIndices,
                                           LogTypeService logTypeService,
                                           ClusterService clusterService,
                                           Settings settings,
                                           ActionFilters actionFilters, CorrelationAlertService correlationAlertService, NotificationService notificationService) {
        super(AlertingActions.SUBSCRIBE_BATCH_FINDINGS_ACTION_NAME, transportService, actionFilters, PublishBatchFindingsRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.correlationIndices = correlationIndices;
        this.correlationRuleIndices = correlationRuleIndices;
        this.logTypeService = logTypeService;
        this.clusterService = clusterService;
        this.settings = settings;
        this.correlationAlertService = correlationAlertService;
        this.notificationService = notificationService;
        this.threadPool = this.detectorIndices.getThreadPool();

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.corrTimeWindow = SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW.get(this.settings).getMillis();
        this.enableAutoCorrelation = SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.get(this.settings);
        this.autoCorrelationTimebox = SecurityAnalyticsSettings.BATCH_AUTO_CORRELATIONS_TIMEBOX.get(this.settings).getMillis();
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.INDEX_TIMEOUT, it -> indexTimeout = it);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW, it -> corrTimeWindow = it.getMillis());
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS, it -> enableAutoCorrelation = it);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.BATCH_AUTO_CORRELATIONS_TIMEBOX, it -> autoCorrelationTimebox = it.getMillis());
        this.setupTimestamp = System.currentTimeMillis();
    }

    @Override
    protected void doExecute(Task task, ActionRequest request, ActionListener<SubscribeFindingsResponse> actionListener) {
        try {
            PublishBatchFindingsRequest transformedRequest = transformRequest(request);
            AsyncCorrelateFindingAction correlateFindingAction = new AsyncCorrelateFindingAction(task, transformedRequest, readUserFromThreadContext(this.threadPool), actionListener);

            if (!enableAutoCorrelation && !correlationRuleIndices.correlationRuleIndexExists()) {
                log.debug("auto correlations is disabled and correlation rules index does not exist, skipping correlations");
                correlateFindingAction.onOperation();
            }

            log.debug("is auto correlations enabled: {}", enableAutoCorrelation);
            log.debug("does correlation rule index exist: {}", correlationRuleIndices.correlationRuleIndexExists());

            // check if there are any correlation rules
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
            searchSourceBuilder.size(1);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(CorrelationRule.CORRELATION_RULE_INDEX);
            searchRequest.source(searchSourceBuilder);
            searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

            client.search(searchRequest,
                    ActionListener.wrap(response -> {
                        if (response.isTimedOut()) {
                            correlateFindingAction.onFailures(new OpenSearchStatusException("Correlation rules search request timed out", RestStatus.REQUEST_TIMEOUT));
                        }

                        SearchHits hits = response.getHits();
                        if (hits.getHits().length == 0) {
                            log.debug("correlations rules index exists but is empty, skipping correlations");
                            correlateFindingAction.onCompletion();
                        }
                    }, correlateFindingAction::onFailures)
            );

            log.debug("either autocorrelations was enabled, or correlation rules are present, proceeding with correlations");

            // proceed with correlating findings
            if (!this.correlationIndices.correlationIndexExists()) {
                try {
                    this.correlationIndices.initCorrelationIndex(ActionListener.wrap(response -> {
                        if (response.isAcknowledged()) {
                            IndexUtils.correlationIndexUpdated();
                            if (IndexUtils.correlationIndexUpdated) {
                                IndexUtils.lastUpdatedCorrelationHistoryIndex = IndexUtils.getIndexNameWithAlias(
                                        clusterService.state(),
                                        CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX
                                );
                            }

                            if (!correlationIndices.correlationMetadataIndexExists()) {
                                try {
                                    correlationIndices.initCorrelationMetadataIndex(ActionListener.wrap(createIndexResponse -> {
                                        if (createIndexResponse.isAcknowledged()) {
                                            IndexUtils.correlationMetadataIndexUpdated();

                                            correlationIndices.setupCorrelationIndex(indexTimeout, setupTimestamp, ActionListener.wrap(bulkResponse -> {
                                                if (bulkResponse.hasFailures()) {
                                                    correlateFindingAction.onFailures(new OpenSearchStatusException(createIndexResponse.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                                }

                                                correlateFindingAction.start();
                                            }, correlateFindingAction::onFailures));
                                        } else {
                                            correlateFindingAction.onFailures(new OpenSearchStatusException("Failed to create correlation metadata Index", RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    }, correlateFindingAction::onFailures));
                                } catch (Exception ex) {
                                    correlateFindingAction.onFailures(ex);
                                }
                            }
                            if (!correlationIndices.correlationAlertIndexExists()) {
                                try {
                                    correlationIndices.initCorrelationAlertIndex(ActionListener.wrap(createIndexResponse -> {
                                        if (createIndexResponse.isAcknowledged()) {
                                            IndexUtils.correlationAlertIndexUpdated();
                                        } else {
                                            correlateFindingAction.onFailures(new OpenSearchStatusException("Failed to create correlation metadata Index", RestStatus.INTERNAL_SERVER_ERROR));
                                        }
                                    }, correlateFindingAction::onFailures));
                                } catch (Exception ex) {
                                    correlateFindingAction.onFailures(ex);
                                }
                            }
                        } else {
                            correlateFindingAction.onFailures(new OpenSearchStatusException("Failed to create correlation Index", RestStatus.INTERNAL_SERVER_ERROR));
                        }
                    }, correlateFindingAction::onFailures));
                } catch (Exception ex) {
                    correlateFindingAction.onFailures(ex);
                }
            } else {
                correlateFindingAction.start();
            }
        } catch (Exception e) {
            throw new SecurityAnalyticsException("Unknown exception occurred", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    public class AsyncCorrelateFindingAction {
        private final PublishBatchFindingsRequest request;
        private final JoinEngine joinEngine;
        private final VectorEmbeddingsEngine vectorEmbeddingsEngine;

        private final ActionListener<SubscribeFindingsResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncCorrelateFindingAction(Task task, PublishBatchFindingsRequest request, User user, ActionListener<SubscribeFindingsResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.response =new AtomicReference<>();
            this.joinEngine = new JoinEngine(client, request, xContentRegistry, corrTimeWindow, indexTimeout, this, logTypeService, enableAutoCorrelation, correlationAlertService, notificationService, user);
            this.vectorEmbeddingsEngine = new VectorEmbeddingsEngine(client, indexTimeout, corrTimeWindow, this);
        }

        void start() {
            TransportCorrelateFindingAction.this.threadPool.getThreadContext().stashContext();
            String monitorId = request.getMonitorId();
            List<Finding> findings = request.getFindings();

            if (detectorIndices.detectorIndexExists()) {
                NestedQueryBuilder queryBuilder =
                        QueryBuilders.nestedQuery(
                                "detector",
                                QueryBuilders.matchQuery(
                                        "detector.monitor_id",
                                        monitorId
                                ),
                                ScoreMode.None
                        );

                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(true);
                searchSourceBuilder.size(1);
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(Detector.DETECTORS_INDEX);
                searchRequest.source(searchSourceBuilder);
                searchRequest.preference(Preference.PRIMARY_FIRST.type());
                searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));

                client.search(searchRequest, ActionListener.wrap(response -> {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                    }

                    SearchHits hits = response.getHits();
                    if (hits.getHits().length > 0) {
                        try {
                            SearchHit hit = hits.getAt(0);

                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );
                            Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                            long startTime = System.currentTimeMillis();
                            log.info("Processing a batch of {} findings", findings.size());
                            for (Finding finding : findings) {
                                long timePast = System.currentTimeMillis() - startTime;
                                log.debug("Time spent processing batch so far: {}", timePast);
                                if (timePast >= autoCorrelationTimebox) {
                                    log.error("Correlation timebox breached after {} millis, skipping rest of findings", autoCorrelationTimebox);
                                    break;
                                }
                                joinEngine.onSearchDetectorResponse(detector, finding);
                            }
                            long endTime = System.currentTimeMillis();
                            log.info("Correlating batch of {} findings took {} seconds to complete", findings.size(), (endTime - startTime) / 1000);
                        } catch (Exception e) {
                            log.error("Exception for request {}", searchRequest.toString(), e);
                            onFailures(e);
                        } finally {
                            onCompletion();
                        }
                    } else {
                        onFailures(new OpenSearchStatusException("detector not found given monitor id " + request.getMonitorId(), RestStatus.INTERNAL_SERVER_ERROR));
                    }
                }, this::onFailures));
            } else {
                onFailures(new SecurityAnalyticsException(String.format(Locale.getDefault(), "Detector index %s doesnt exist", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR, new RuntimeException()));
            }
        }

        public void initCorrelationIndex(String detectorType, Finding finding, Map<String, List<String>> correlatedFindings, List<String> correlationRules) {
            try {
                if (!IndexUtils.correlationIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                            CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX,
                            CorrelationIndices.correlationMappings(), clusterService.state(), client.admin().indices(),
                            ActionListener.wrap(response -> {
                                if (response.isAcknowledged()) {
                                    IndexUtils.correlationIndexUpdated();
                                    getTimestampFeature(detectorType, finding, correlatedFindings, null, correlationRules);
                                } else {
                                    onFailures(new OpenSearchStatusException("Failed to create correlation Index", RestStatus.INTERNAL_SERVER_ERROR));
                                }
                            }, this::onFailures),
                            true
                    );
                } else {
                    getTimestampFeature(detectorType, finding, correlatedFindings, null, correlationRules);
                }
            } catch (Exception ex) {
                onFailures(ex);
            }
        }

        public void getTimestampFeature(String detectorType, Finding finding, Map<String, List<String>> correlatedFindings, Finding orphanFinding, List<String> correlationRules) {
            try {
                if (!correlationIndices.correlationMetadataIndexExists()) {
                        correlationIndices.initCorrelationMetadataIndex(ActionListener.wrap(response -> {
                            if (response.isAcknowledged()) {
                                IndexUtils.correlationMetadataIndexUpdated();

                                correlationIndices.setupCorrelationIndex(indexTimeout, setupTimestamp, ActionListener.wrap(bulkResponse -> {
                                    if (bulkResponse.hasFailures()) {
                                        onFailures(new OpenSearchStatusException(bulkResponse.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                    }

                                    long findingTimestamp = finding.getTimestamp().toEpochMilli();
                                    SearchRequest searchMetadataIndexRequest = getSearchMetadataIndexRequest();

                                    client.search(searchMetadataIndexRequest, ActionListener.wrap(searchMetadataResponse -> {
                                        if (searchMetadataResponse.getHits().getHits().length == 0) {
                                            onFailures(new ResourceNotFoundException(
                                                    "Failed to find hits in metadata index for finding id {}", finding.getId()));
                                        }

                                        String id = searchMetadataResponse.getHits().getHits()[0].getId();
                                        Map<String, Object> hitSource = searchMetadataResponse.getHits().getHits()[0].getSourceAsMap();
                                        long scoreTimestamp = (long) hitSource.get("scoreTimestamp");

                                        long newScoreTimestamp = findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL;
                                        if (newScoreTimestamp > scoreTimestamp) {
                                            try {
                                                IndexRequest scoreIndexRequest = getCorrelationMetadataIndexRequest(id, newScoreTimestamp);

                                                client.index(scoreIndexRequest, ActionListener.wrap(indexResponse -> {
                                                    SearchRequest searchRequest = getSearchLogTypeIndexRequest();

                                                    client.search(searchRequest, ActionListener.wrap(searchResponse -> {
                                                        if (searchResponse.isTimedOut()) {
                                                            onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                                        }

                                                        SearchHit[] hits = searchResponse.getHits().getHits();
                                                        Map<String, CustomLogType> logTypes = new HashMap<>();
                                                        for (SearchHit hit : hits) {
                                                            Map<String, Object> sourceMap = hit.getSourceAsMap();
                                                            logTypes.put(sourceMap.get("name").toString(),
                                                                    new CustomLogType(sourceMap));
                                                        }

                                                        if (correlatedFindings != null) {
                                                            if (correlatedFindings.isEmpty()) {
                                                                vectorEmbeddingsEngine.insertOrphanFindings(detectorType, finding, Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue(), logTypes);
                                                            }
                                                            for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                                                                vectorEmbeddingsEngine.insertCorrelatedFindings(detectorType, finding, correlatedFinding.getKey(), correlatedFinding.getValue(),
                                                                        Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue(), correlationRules, logTypes);
                                                            }
                                                        } else {
                                                            vectorEmbeddingsEngine.insertOrphanFindings(detectorType, orphanFinding, Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue(), logTypes);
                                                        }
                                                    }, this::onFailures));
                                                }, this::onFailures));
                                            } catch (Exception ex) {
                                                onFailures(ex);
                                            }
                                        } else {
                                            float timestampFeature = Long.valueOf((findingTimestamp - scoreTimestamp) / 1000L).floatValue();

                                            SearchRequest searchRequest =  getSearchLogTypeIndexRequest();
                                            insertFindings(timestampFeature, searchRequest, finding, correlatedFindings, detectorType, correlationRules, orphanFinding);
                                        }
                                    }, this::onFailures));
                                }, this::onFailures));
                            } else {
                                Exception e = new OpenSearchStatusException("Failed to create correlation metadata Index", RestStatus.INTERNAL_SERVER_ERROR);
                                onFailures(e);
                            }
                        }, this::onFailures));
                } else {
                    long findingTimestamp = finding.getTimestamp().toEpochMilli();
                    SearchRequest searchMetadataIndexRequest = getSearchMetadataIndexRequest();

                    client.search(searchMetadataIndexRequest, ActionListener.wrap(response -> {
                        if (response.getHits().getHits().length == 0) {
                            onFailures(new ResourceNotFoundException(
                                    "Failed to find hits in metadata index for finding id {}", finding.getId()));
                        } else {
                            String id = response.getHits().getHits()[0].getId();
                            Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                            long scoreTimestamp = (long) hitSource.get("scoreTimestamp");

                            long newScoreTimestamp = findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL;
                            if (newScoreTimestamp > scoreTimestamp) {
                                IndexRequest scoreIndexRequest = getCorrelationMetadataIndexRequest(id, newScoreTimestamp);

                                client.index(scoreIndexRequest, ActionListener.wrap(indexResponse -> {
                                    SearchRequest searchRequest = getSearchLogTypeIndexRequest();

                                    client.search(searchRequest, ActionListener.wrap(searchResponse -> {
                                        if (searchResponse.isTimedOut()) {
                                            onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                                        }

                                        SearchHit[] hits = searchResponse.getHits().getHits();
                                        Map<String, CustomLogType> logTypes = new HashMap<>();
                                        for (SearchHit hit : hits) {
                                            Map<String, Object> sourceMap = hit.getSourceAsMap();
                                            logTypes.put(sourceMap.get("name").toString(), new CustomLogType(sourceMap));
                                        }

                                        if (correlatedFindings != null) {
                                            if (correlatedFindings.isEmpty()) {
                                                vectorEmbeddingsEngine.insertOrphanFindings(detectorType, finding, Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue(), logTypes);
                                            }
                                            for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                                                vectorEmbeddingsEngine.insertCorrelatedFindings(detectorType, finding, correlatedFinding.getKey(), correlatedFinding.getValue(),
                                                        Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue(), correlationRules, logTypes);
                                            }
                                        } else {
                                            vectorEmbeddingsEngine.insertOrphanFindings(detectorType, orphanFinding, Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue(), logTypes);
                                        }
                                    }, this::onFailures));
                                }, this::onFailures));
                            } else {
                                float timestampFeature = Long.valueOf((findingTimestamp - scoreTimestamp) / 1000L).floatValue();

                                SearchRequest searchRequest = getSearchLogTypeIndexRequest();
                                insertFindings(timestampFeature, searchRequest, finding, correlatedFindings, detectorType, correlationRules, orphanFinding);
                            }
                        }
                    }, this::onFailures));
                }
            } catch (Exception ex) {
                onFailures(ex);
            }
        }

        private SearchRequest getSearchLogTypeIndexRequest() {
            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                    .must(QueryBuilders.existsQuery("source"));
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            searchSourceBuilder.size(10000);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
            searchRequest.source(searchSourceBuilder);
            searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30L));
            return searchRequest;
        }

        private IndexRequest getCorrelationMetadataIndexRequest(String id, long newScoreTimestamp) throws IOException {
            XContentBuilder scoreBuilder = XContentFactory.jsonBuilder().startObject();
            scoreBuilder.field("scoreTimestamp", newScoreTimestamp);
            scoreBuilder.field("root", false);
            scoreBuilder.endObject();

            return new IndexRequest(CorrelationIndices.CORRELATION_METADATA_INDEX)
                    .id(id)
                    .source(scoreBuilder)
                    .timeout(indexTimeout)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        }

        private void insertFindings(float timestampFeature, SearchRequest searchRequest, Finding finding, Map<String, List<String>> correlatedFindings, String detectorType, List<String> correlationRules, Finding orphanFinding) {
            client.search(searchRequest, ActionListener.wrap(response -> {
                if (response.isTimedOut()) {
                    onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                }

                SearchHit[] hits = response.getHits().getHits();
                Map<String, CustomLogType> logTypes = new HashMap<>();
                for (SearchHit hit : hits) {
                    Map<String, Object> sourceMap = hit.getSourceAsMap();
                    logTypes.put(sourceMap.get("name").toString(),
                            new CustomLogType(sourceMap));
                }

                if (correlatedFindings != null) {
                    if (correlatedFindings.isEmpty()) {
                        vectorEmbeddingsEngine.insertOrphanFindings(detectorType, finding, timestampFeature, logTypes);
                    }
                    for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                        vectorEmbeddingsEngine.insertCorrelatedFindings(detectorType, finding, correlatedFinding.getKey(), correlatedFinding.getValue(),
                                timestampFeature, correlationRules, logTypes);
                    }
                } else {
                    vectorEmbeddingsEngine.insertOrphanFindings(detectorType, orphanFinding, timestampFeature, logTypes);
                }
            }, this::onFailures));
        }

        private SearchRequest getSearchMetadataIndexRequest() {
            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                    .mustNot(QueryBuilders.termQuery("scoreTimestamp", 0L));
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

        public void onCompletion() {
            this.response.set(RestStatus.OK);
            if (counter.compareAndSet(false, true)) {
                finishHim(null);
            }
        }

        public void onOperation() {
            String findingIds = request.getFindings().stream().map(Finding::getId).collect(Collectors.joining(", "));
            log.debug("Successfully correlated finding ids {} for monitor id {}",
                    findingIds, request.getMonitorId());
        }

        public void onFailures(Exception t) {
            String findingIds = request.getFindings().stream().map(Finding::getId).collect(Collectors.joining(", "));
            log.error("Exception occurred while processing correlations for finding ids {} and monitor id {}",
                    findingIds, request.getMonitorId(), t);
        }

        private void finishHim(Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new SubscribeFindingsResponse(RestStatus.OK);
                }
            }));
        }
    }

    private PublishBatchFindingsRequest transformRequest(ActionRequest request) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStreamStreamOutput osso = new OutputStreamStreamOutput(baos);
        request.writeTo(osso);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamStreamInput issi = new InputStreamStreamInput(bais);
        return new PublishBatchFindingsRequest(issi);
    }
}