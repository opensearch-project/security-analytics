/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.InputStreamStreamInput;
import org.opensearch.common.io.stream.OutputStreamStreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.commons.alerting.action.PublishFindingsRequest;
import org.opensearch.commons.alerting.action.SubscribeFindingsResponse;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.correlation.JoinEngine;
import org.opensearch.securityanalytics.correlation.VectorEmbeddingsEngine;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class TransportCorrelateFindingAction extends HandledTransportAction<ActionRequest, SubscribeFindingsResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportCorrelateFindingAction.class);

    private final DetectorIndices detectorIndices;

    private final CorrelationIndices correlationIndices;

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private volatile TimeValue indexTimeout;

    private volatile long corrTimeWindow;

    private volatile long setupTimestamp;

    @Inject
    public TransportCorrelateFindingAction(TransportService transportService,
                                           Client client,
                                           NamedXContentRegistry xContentRegistry,
                                           DetectorIndices detectorIndices,
                                           CorrelationIndices correlationIndices,
                                           ClusterService clusterService,
                                           Settings settings,
                                           ActionFilters actionFilters) {
        super(AlertingActions.SUBSCRIBE_FINDINGS_ACTION_NAME, transportService, actionFilters, PublishFindingsRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.correlationIndices = correlationIndices;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.detectorIndices.getThreadPool();

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.corrTimeWindow = SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW.get(this.settings).getMillis();
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.INDEX_TIMEOUT, it -> indexTimeout = it);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.CORRELATION_TIME_WINDOW, it -> corrTimeWindow = it.getMillis());
        this.setupTimestamp = System.currentTimeMillis();
    }

    @Override
    protected void doExecute(Task task, ActionRequest request, ActionListener<SubscribeFindingsResponse> actionListener) {
        try {
            PublishFindingsRequest transformedRequest = transformRequest(request);

            if (!this.correlationIndices.correlationIndexExists()) {
                try {
                    this.correlationIndices.initCorrelationIndex(new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            if (response.isAcknowledged()) {
                                IndexUtils.correlationIndexUpdated();
                                correlationIndices.setupCorrelationIndex(indexTimeout, setupTimestamp, new ActionListener<BulkResponse>() {
                                    @Override
                                    public void onResponse(BulkResponse response) {
                                        if (response.hasFailures()) {
                                            log.error(new OpenSearchStatusException(response.toString(), RestStatus.INTERNAL_SERVER_ERROR));
                                        }

                                        AsyncCorrelateFindingAction correlateFindingAction = new AsyncCorrelateFindingAction(task, transformedRequest, actionListener);
                                        correlateFindingAction.start();
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        log.error(e);
                                    }
                                });
                            } else {
                                log.error(new OpenSearchStatusException("Failed to create correlation Index", RestStatus.INTERNAL_SERVER_ERROR));
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(e);
                        }
                    });
                } catch (IOException ex) {
                    log.error(ex);
                }
            } else {
                AsyncCorrelateFindingAction correlateFindingAction = new AsyncCorrelateFindingAction(task, transformedRequest, actionListener);
                correlateFindingAction.start();
            }
        } catch (IOException e) {
            throw new SecurityAnalyticsException("Unknown exception occurred", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    public class AsyncCorrelateFindingAction {
        private final PublishFindingsRequest request;
        private final JoinEngine joinEngine;
        private final VectorEmbeddingsEngine vectorEmbeddingsEngine;

        private final ActionListener<SubscribeFindingsResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncCorrelateFindingAction(Task task, PublishFindingsRequest request, ActionListener<SubscribeFindingsResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response =new AtomicReference<>();

            this.joinEngine = new JoinEngine(client, request, xContentRegistry, corrTimeWindow, this);
            this.vectorEmbeddingsEngine = new VectorEmbeddingsEngine(client, indexTimeout, corrTimeWindow, this);
        }

        void start() {
            TransportCorrelateFindingAction.this.threadPool.getThreadContext().stashContext();
            String monitorId = request.getMonitorId();
            Finding finding = request.getFinding();

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

                client.search(searchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                        }

                        SearchHits hits = response.getHits();
                        if (hits.getTotalHits().value == 1) {
                            try {
                                SearchHit hit = hits.getAt(0);

                                XContentParser xcp = XContentType.JSON.xContent().createParser(
                                        xContentRegistry,
                                        LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                                );
                                Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                                joinEngine.onSearchDetectorResponse(detector, finding);
                            } catch (IOException e) {
                                onFailures(e);
                            }
                        } else {
                            onFailures(new OpenSearchStatusException("detector not found given monitor id", RestStatus.INTERNAL_SERVER_ERROR));
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                onFailures(new SecurityAnalyticsException(String.format(Locale.getDefault(), "Detector index %s doesnt exist", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR, new RuntimeException()));
            }
        }

        public void initCorrelationIndex(String detectorType, Map<String, List<String>> correlatedFindings) {
            try {
                if (!IndexUtils.correlationIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                            CorrelationIndices.CORRELATION_INDEX,
                            CorrelationIndices.correlationMappings(), clusterService.state(), client.admin().indices(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    if (response.isAcknowledged()) {
                                        IndexUtils.correlationIndexUpdated();
                                        getTimestampFeature(detectorType, correlatedFindings, null);
                                    } else {
                                        onFailures(new OpenSearchStatusException("Failed to create correlation Index", RestStatus.INTERNAL_SERVER_ERROR));
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            }
                    );
                } else {
                    getTimestampFeature(detectorType, correlatedFindings, null);
                }
            } catch (IOException ex) {
                onFailures(ex);
            }
        }

        public void getTimestampFeature(String detectorType, Map<String, List<String>> correlatedFindings, Finding orphanFinding) {
            long findingTimestamp = this.request.getFinding().getTimestamp().toEpochMilli();
            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                    .mustNot(QueryBuilders.termQuery("scoreTimestamp", 0L));
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
                    String id = response.getHits().getHits()[0].getId();
                    Map<String, Object> hitSource = response.getHits().getHits()[0].getSourceAsMap();
                    long scoreTimestamp = (long) hitSource.get("scoreTimestamp");

                    if (findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL > scoreTimestamp) {
                        try {
                            XContentBuilder scoreBuilder = XContentFactory.jsonBuilder().startObject();
                            scoreBuilder.field("scoreTimestamp", findingTimestamp - CorrelationIndices.FIXED_HISTORICAL_INTERVAL);
                            scoreBuilder.field("root", false);
                            scoreBuilder.endObject();

                            IndexRequest scoreIndexRequest = new IndexRequest(CorrelationIndices.CORRELATION_INDEX)
                                    .id(id)
                                    .source(scoreBuilder)
                                    .timeout(indexTimeout)
                                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                            client.index(scoreIndexRequest, new ActionListener<>() {
                                @Override
                                public void onResponse(IndexResponse response) {
                                    if (correlatedFindings != null) {
                                        if (correlatedFindings.isEmpty()) {
                                            vectorEmbeddingsEngine.insertOrphanFindings(detectorType, request.getFinding(), Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue());
                                        }
                                        for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                                            vectorEmbeddingsEngine.insertCorrelatedFindings(detectorType, request.getFinding(), correlatedFinding.getKey(), correlatedFinding.getValue(),
                                                    Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue());
                                        }
                                    } else {
                                        vectorEmbeddingsEngine.insertOrphanFindings(detectorType, orphanFinding, Long.valueOf(CorrelationIndices.FIXED_HISTORICAL_INTERVAL / 1000L).floatValue());
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            });
                        } catch (Exception ex) {
                            onFailures(ex);
                        }
                    } else {
                        float timestampFeature = Long.valueOf((findingTimestamp - scoreTimestamp) / 1000L).floatValue();
                        if (correlatedFindings != null) {
                            if (correlatedFindings.isEmpty()) {
                                vectorEmbeddingsEngine.insertOrphanFindings(detectorType, request.getFinding(), timestampFeature);
                            }
                            for (Map.Entry<String, List<String>> correlatedFinding : correlatedFindings.entrySet()) {
                                vectorEmbeddingsEngine.insertCorrelatedFindings(detectorType, request.getFinding(), correlatedFinding.getKey(), correlatedFinding.getValue(),
                                        timestampFeature);
                            }
                        } else {
                            vectorEmbeddingsEngine.insertOrphanFindings(detectorType, orphanFinding, timestampFeature);
                        }
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        public void onOperation() {
            this.response.set(RestStatus.OK);
            if (counter.compareAndSet(false, true)) {
                finishHim(null);
            }
        }

        public void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(t);
            }
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

    private PublishFindingsRequest transformRequest(ActionRequest request) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStreamStreamOutput osso = new OutputStreamStreamOutput(baos);
        request.writeTo(osso);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamStreamInput issi = new InputStreamStreamInput(bais);
        return new PublishFindingsRequest(issi);
    }
}