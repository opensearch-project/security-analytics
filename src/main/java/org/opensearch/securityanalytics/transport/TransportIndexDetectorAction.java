/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.Build;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParser.Token;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtAggregationBuilder;
import org.opensearch.commons.alerting.model.BucketLevelTrigger;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.DocumentLevelTrigger;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.commons.alerting.model.SearchInput;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.plugins.SearchPlugin.AggregationSpec;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.script.Script;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.AggregatorFactories;
import org.opensearch.search.aggregations.AggregatorFactories.Builder;
import org.opensearch.search.aggregations.BaseAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.DoubleTerms;
import org.opensearch.search.aggregations.bucket.terms.LongTerms;
import org.opensearch.search.aggregations.bucket.terms.StringTerms;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.UnmappedTerms;
import org.opensearch.search.aggregations.metrics.AvgAggregationBuilder;
import org.opensearch.search.aggregations.metrics.InternalValueCount;
import org.opensearch.search.aggregations.metrics.ValueCountAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportIndexDetectorAction extends HandledTransportAction<IndexDetectorRequest, IndexDetectorResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexDetectorAction.class);

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final DetectorIndices detectorIndices;

    private final RuleTopicIndices ruleTopicIndices;

    private final RuleIndices ruleIndices;

    private final MapperService mapperService;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final Settings settings;

    private volatile TimeValue indexTimeout;

    @Inject
    public TransportIndexDetectorAction(TransportService transportService, Client client, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, DetectorIndices detectorIndices, RuleTopicIndices ruleTopicIndices, RuleIndices ruleIndices, MapperService mapperService, ClusterService clusterService, Settings settings) {
        super(IndexDetectorAction.NAME, transportService, actionFilters, IndexDetectorRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.ruleTopicIndices = ruleTopicIndices;
        this.ruleIndices = ruleIndices;
        this.mapperService = mapperService;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.detectorIndices.getThreadPool();

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
    }

    @Override
    protected void doExecute(Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
        AsyncIndexDetectorsAction asyncAction = new AsyncIndexDetectorsAction(task, request, listener);
        asyncAction.start();
    }

    private void createMonitorFromQueries(String index, List<Pair<String, Rule>> rulesById, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy){
        List<Pair<String, Rule>> docLevelRules = rulesById.stream().filter(it -> !it.getRight().isAggregationRule()).collect(
            Collectors.toList());
        List<Pair<String, Rule>> bucketLevelRules = rulesById.stream().filter(it -> it.getRight().isAggregationRule()).collect(
            Collectors.toList());

        createAlertingMonitorFromQueries(Pair.of(index, docLevelRules), detector, listener, refreshPolicy);
        createBucketMonitorFromQueries(Pair.of(index, bucketLevelRules), detector, listener, refreshPolicy);
    }

    private void createAlertingMonitorFromQueries(Pair<String, List<Pair<String, Rule>>> logIndexToQueries, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();

        List<DocLevelQuery> docLevelQueries = new ArrayList<>();

        for (Pair<String, Rule> query: logIndexToQueries.getRight()) {
            String id = query.getLeft();

            Rule rule = query.getRight();
            String name = query.getLeft();

            String actualQuery = rule.getQueries().get(0).getValue();

            List<String> tags = new ArrayList<>();
            tags.add(rule.getLevel());
            tags.add(rule.getCategory());
            tags.addAll(rule.getTags().stream().map(Value::getValue).collect(Collectors.toList()));

            DocLevelQuery docLevelQuery = new DocLevelQuery(id, name, actualQuery, tags);
            docLevelQueries.add(docLevelQuery);
        }
        DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(detector.getName(), List.of(logIndexToQueries.getKey()), docLevelQueries);
        docLevelMonitorInputs.add(docLevelMonitorInput);

        List<DocumentLevelTrigger> triggers = new ArrayList<>();
        List<DetectorTrigger> detectorTriggers = detector.getTriggers();

        for (DetectorTrigger detectorTrigger: detectorTriggers) {
            String id = detectorTrigger.getId();
            String name = detectorTrigger.getName();
            String severity = detectorTrigger.getSeverity();
            List<Action> actions = detectorTrigger.getActions();
            Script condition = detectorTrigger.convertToCondition();

            triggers.add(new DocumentLevelTrigger(id, name, severity, actions, condition));
        }

        Monitor monitor = new Monitor(Monitor.NO_ID, Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
                Monitor.MonitorType.DOC_LEVEL_MONITOR, detector.getUser(), 1, docLevelMonitorInputs, triggers, Map.of(),
                new DataSources(detector.getRuleIndex(),
                        detector.getFindingsIndex(),
                        detector.getFindingsIndexPattern(),
                        detector.getAlertsIndex(),
                        detector.getAlertsHistoryIndex(),
                        detector.getAlertsHistoryIndexPattern(),
                        DetectorMonitorConfig.getRuleIndexMappingsByType(detector.getDetectorType())));

        IndexMonitorRequest indexMonitorRequest = new IndexMonitorRequest(Monitor.NO_ID, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, RestRequest.Method.POST, monitor);
        AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, indexMonitorRequest, listener);
    }

    private void createBucketMonitorFromQueries(Pair<String, List<Pair<String, Rule>>> logIndexToQueries, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) {
        try {
            for (Pair<String, Rule> query: logIndexToQueries.getRight()) {
                Rule rule = query.getRight();

                // TODO -> Create Bucket level monitor; Per each bucket rule new monitor or?
                if(rule.getAggregationQueries() != null){
                    // Create aggregation queries
                    XContentParser aggregationQueriesParser = XContentFactory.xContent(XContentType.JSON)
                        .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,  rule.getAggregationQueries().get(0).getValue());
                    AggregationQueries aggregationQueries = AggregationQueries.docParse(aggregationQueriesParser);

                    // Building QueryString
                    QueryBuilder queryBuilder =
                        QueryBuilders.queryStringQuery(rule.getQueries().get(0).getValue());


                    NamedXContentRegistry registry = new NamedXContentRegistry(
                        getDefaultNamedXContents()
                    );
                    XContentParser aggregationQueryParser = XContentFactory.xContent(XContentType.JSON)
                        .createParser(registry, LoggingDeprecationHandler.INSTANCE,   aggregationQueries.getAggQuery());
                    aggregationQueryParser.nextToken();
                    // TODO - Probably not the correct way to go; Need to see how to parse aggQueries once the rule is being converted
                    AggregationBuilder aggregationBuilder = AggregatorFactories.parseAggregators(aggregationQueryParser).getAggregatorFactories().iterator().next();

                    SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                        .seqNoAndPrimaryTerm(true)
                        .version(true)
                        .query(queryBuilder)
                        .aggregation(aggregationBuilder)
                        .size(10000);

                    List<SearchInput> bucketLevelMonitorInputs = new ArrayList<>();
                    bucketLevelMonitorInputs.add(new SearchInput(Arrays.asList(logIndexToQueries.getKey()), searchSourceBuilder));

                    // Bucket level monitor will always have one aggregation and therefore one bucket condition
                    XContentParser bucketConditionParser = XContentFactory.xContent(XContentType.JSON)
                        .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,  aggregationQueries.getBucketTriggerQuery());
                    XContentParserUtils.ensureExpectedToken(Token.START_OBJECT, bucketConditionParser.nextToken(), bucketConditionParser);
                    BucketSelectorExtAggregationBuilder bucketSelectorBuilder = BucketSelectorExtAggregationBuilder.Companion.parse("condition", bucketConditionParser);

                    List<DetectorTrigger> detectorTriggers = detector.getTriggers();
                    List<BucketLevelTrigger> triggers = new ArrayList<>();

                    for (DetectorTrigger detectorTrigger: detectorTriggers) {
                        String id = detectorTrigger.getId();
                        String name = detectorTrigger.getName();
                        String severity = detectorTrigger.getSeverity();
                        List<Action> actions = detectorTrigger.getActions();
                        BucketLevelTrigger bucketLevelTrigger = new BucketLevelTrigger(id, name, severity, bucketSelectorBuilder, actions);
                        triggers.add(bucketLevelTrigger);
                    }

                    DataSources dataSources = new DataSources(detector.getRuleIndex(),
                        detector.getFindingIndex(),
                        null,
                        detector.getAlertIndex(),
                        null,
                        null,
                        DetectorMonitorConfig.getRuleIndexMappingsByType(detector.getDetectorType()));

                    Monitor monitor = new Monitor(Monitor.NO_ID, Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
                        MonitorType.BUCKET_LEVEL_MONITOR, detector.getUser(), 1, bucketLevelMonitorInputs, triggers, Map.of(),
                        dataSources);

                    IndexMonitorRequest indexMonitorRequest = new IndexMonitorRequest(Monitor.NO_ID, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, RestRequest.Method.POST, monitor);
                    AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, indexMonitorRequest, listener);
                }
            }
        } catch (Exception ex) {
            // TODO - how to handle
        }
    }

    static List<NamedXContentRegistry.Entry> getDefaultNamedXContents() {
        AggregationSpec aggregationSpec = new AggregationSpec(AvgAggregationBuilder.NAME, AvgAggregationBuilder::new, AvgAggregationBuilder.PARSER)
            .addResultReader(InternalValueCount::new)
            .setAggregatorRegistrar(AvgAggregationBuilder::registerAggregators);


        NamedXContentRegistry.Entry entry = new NamedXContentRegistry.Entry(BaseAggregationBuilder.class, aggregationSpec.getName(), (p, c) -> {
            String name = (String) c;
            return aggregationSpec.getParser().parse(p, name);
        });

        AggregationSpec terms = new AggregationSpec(TermsAggregationBuilder.NAME, TermsAggregationBuilder::new, TermsAggregationBuilder.PARSER).addResultReader(
                StringTerms.NAME,
                StringTerms::new
            )
            .addResultReader(UnmappedTerms.NAME, UnmappedTerms::new)
            .addResultReader(LongTerms.NAME, LongTerms::new)
            .addResultReader(DoubleTerms.NAME, DoubleTerms::new)
            .setAggregatorRegistrar(TermsAggregationBuilder::registerAggregators);


        NamedXContentRegistry.Entry entryTerm = new NamedXContentRegistry.Entry(BaseAggregationBuilder.class, terms.getName(), (p, c) -> {
            String name = (String) c;
            return terms.getParser().parse(p, name);
        });

        return Arrays.asList(entry, entryTerm);
    }


    private void updateAlertingMonitorFromQueries(Pair<String, List<Pair<String, Rule>>> logIndexToQueries, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();

        List<DocLevelQuery> docLevelQueries = new ArrayList<>();

        for (Pair<String, Rule> query: logIndexToQueries.getRight()) {
            String id = query.getLeft();

            Rule rule = query.getRight();
            String name = query.getLeft();

            String actualQuery = rule.getQueries().get(0).getValue();

            List<String> tags = new ArrayList<>();
            tags.add(rule.getLevel());
            tags.add(rule.getCategory());
            tags.addAll(rule.getTags().stream().map(Value::getValue).collect(Collectors.toList()));

            DocLevelQuery docLevelQuery = new DocLevelQuery(id, name, actualQuery, tags);
            docLevelQueries.add(docLevelQuery);
        }
        DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(detector.getName(), List.of(logIndexToQueries.getKey()), docLevelQueries);
        docLevelMonitorInputs.add(docLevelMonitorInput);

        List<DocumentLevelTrigger> triggers = new ArrayList<>();
        List<DetectorTrigger> detectorTriggers = detector.getTriggers();

        for (DetectorTrigger detectorTrigger: detectorTriggers) {
            String id = detectorTrigger.getId();
            String name = detectorTrigger.getName();
            String severity = detectorTrigger.getSeverity();
            List<Action> actions = detectorTrigger.getActions();
            Script condition = detectorTrigger.convertToCondition();

            triggers.add(new DocumentLevelTrigger(id, name, severity, actions, condition));
        }

        Monitor monitor = new Monitor(detector.getMonitorIds().get(0), Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
                Monitor.MonitorType.DOC_LEVEL_MONITOR, detector.getUser(), 1, docLevelMonitorInputs, triggers, Map.of(),
                new DataSources(detector.getRuleIndex(),
                        detector.getFindingsIndex(),
                        detector.getFindingsIndexPattern(),
                        detector.getAlertsIndex(),
                        detector.getAlertsHistoryIndex(),
                        detector.getAlertsHistoryIndexPattern(),
                        DetectorMonitorConfig.getRuleIndexMappingsByType(detector.getDetectorType())));

        IndexMonitorRequest indexMonitorRequest = new IndexMonitorRequest(detector.getMonitorIds().get(0), SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, RestRequest.Method.PUT, monitor);
        AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, indexMonitorRequest, listener);
    }

    private void onCreateMappingsResponse(CreateIndexResponse response) throws IOException {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Created %s with mappings.", Detector.DETECTORS_INDEX));
            IndexUtils.detectorIndexUpdated();
        } else {
            log.error(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged.", Detector.DETECTORS_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void onUpdateMappingsResponse(AcknowledgedResponse response) {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Updated  %s with mappings.", Detector.DETECTORS_INDEX));
            IndexUtils.detectorIndexUpdated();
        } else {
            log.error(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", Detector.DETECTORS_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    class AsyncIndexDetectorsAction {
        private final IndexDetectorRequest request;

        private final ActionListener<IndexDetectorResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncIndexDetectorsAction(Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            try {
                if (!detectorIndices.detectorIndexExists()) {
                    detectorIndices.initDetectorIndex(new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            try {
                                onCreateMappingsResponse(response);
                                prepareDetectorIndexing();
                            } catch (IOException e) {
                                onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                } else if (!IndexUtils.detectorIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                            Detector.DETECTORS_INDEX,
                            DetectorIndices.detectorMappings(), clusterService.state(), client.admin().indices(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    onUpdateMappingsResponse(response);
                                    try {
                                        prepareDetectorIndexing();
                                    } catch (IOException e) {
                                        onFailures(e);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            }
                    );
                } else {
                    prepareDetectorIndexing();
                }
            } catch (IOException e) {
                onFailures(e);
            }
        }

        void prepareDetectorIndexing() throws IOException {
            if (request.getMethod() == RestRequest.Method.POST) {
                createDetector();
            } else if (request.getMethod() == RestRequest.Method.PUT) {
                updateDetector();
            }
        }

        void createDetector() {
            Detector detector = request.getDetector();

            String ruleTopic = detector.getDetectorType();

            request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndexPattern(DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            request.getDetector().setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            request.getDetector().setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));
            request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));

            if (!detector.getInputs().isEmpty()) {
                try {
                    ruleTopicIndices.initRuleTopicIndex(detector.getRuleIndex(), new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse createIndexResponse) {

                            initRuleIndexAndImportRules(request, new ActionListener<>() {
                                @Override
                                public void onResponse(IndexMonitorResponse indexMonitorResponse) {
                                    request.getDetector().setMonitorIds(List.of(indexMonitorResponse.getId()));
                                    try {
                                        indexDetector();
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
                } catch (IOException e) {
                    onFailures(e);
                }
            }
        }

        void updateDetector() {
            String id = request.getDetectorId();

            GetRequest request = new GetRequest(Detector.DETECTORS_INDEX, id);
            client.get(request, new ActionListener<>() {
                @Override
                public void onResponse(GetResponse response) {
                    if (!response.isExists()) {
                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Detector with %s is not found", id), RestStatus.NOT_FOUND));
                        return;
                    }

                    try {
                        XContentParser xcp = XContentHelper.createParser(
                                xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                response.getSourceAsBytesRef(), XContentType.JSON
                        );

                        Detector detector = Detector.docParse(xcp, response.getId(), response.getVersion());
                        onGetResponse(detector);
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

        void onGetResponse(Detector currentDetector) {
            if (request.getDetector().getEnabled() && currentDetector.getEnabled()) {
                request.getDetector().setEnabledTime(currentDetector.getEnabledTime());
            }
            request.getDetector().setMonitorIds(currentDetector.getMonitorIds());
            Detector detector = request.getDetector();

            String ruleTopic = detector.getDetectorType();

            request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndexPattern(DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            request.getDetector().setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            request.getDetector().setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));
            request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));

            if (!detector.getInputs().isEmpty()) {
                try {
                    ruleTopicIndices.initRuleTopicIndex(detector.getRuleIndex(), new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse createIndexResponse) {
                            initRuleIndexAndImportRules(request, new ActionListener<>() {
                                @Override
                                public void onResponse(IndexMonitorResponse indexMonitorResponse) {
                                    request.getDetector().setMonitorIds(List.of(indexMonitorResponse.getId()));
                                    try {
                                        indexDetector();
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
                } catch (IOException e) {
                    onFailures(e);
                }
            }
        }

        public void initRuleIndexAndImportRules(IndexDetectorRequest request, ActionListener<IndexMonitorResponse> listener) {
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
                                                importRules(request, listener);
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
                                                        importRules(request, listener);
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
                            if (response.isTimedOut()) {
                                onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                            }

                            long count = response.getHits().getTotalHits().value;
                            if (count == 0) {
                                ruleIndices.importRules(WriteRequest.RefreshPolicy.IMMEDIATE, indexTimeout,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(BulkResponse response) {
                                                if (!response.hasFailures()) {
                                                    importRules(request, listener);
                                                } else {
                                                    onFailures(new OpenSearchStatusException(response.buildFailureMessage(), RestStatus.INTERNAL_SERVER_ERROR));
                                                }
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                onFailures(e);
                                            }
                                        });
                            } else {
                                importRules(request, listener);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    }
            );
        }

        @SuppressWarnings("unchecked")
        public void importRules(IndexDetectorRequest request, ActionListener<IndexMonitorResponse> listener) {
            final Detector detector = request.getDetector();
            final String ruleTopic = detector.getDetectorType();
            final DetectorInput detectorInput = detector.getInputs().get(0);
            final String logIndex = detectorInput.getIndices().get(0);

            List<String> ruleIds = detectorInput.getPrePackagedRules().stream().map(DetectorRule::getId).collect(Collectors.toList());

            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery("rule",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery("rule.category", ruleTopic)
                            ).must(
                                    QueryBuilders.termsQuery("_id", ruleIds.toArray(new String[]{}))
                            ),
                            ScoreMode.Avg
                    );

            SearchRequest searchRequest = new SearchRequest(Rule.PRE_PACKAGED_RULES_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(10000));

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }

                    SearchHits hits = response.getHits();
                    List<Pair<String, Rule>> queries = new ArrayList<>();

                    try {
                        for (SearchHit hit: hits) {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );

                            Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
                            String id = hit.getId();

                            queries.add(Pair.of(id, rule));
                        }

                        if (ruleIndices.ruleIndexExists(false)) {
                            importCustomRules(detector, detectorInput, queries, listener);
                        } else if (detectorInput.getCustomRules().size() > 0) {
                            onFailures(new OpenSearchStatusException("Custom Rule Index not found", RestStatus.BAD_REQUEST));
                        } else {
                            Pair<String, List<Pair<String, Rule>>> logIndexToQueries = Pair.of(logIndex, queries);

                            if (request.getMethod() == RestRequest.Method.POST) {
                                createMonitorFromQueries(logIndex, queries, detector, listener, request.getRefreshPolicy());
                                //createAlertingMonitorFromQueries(logIndexToQueries, detector, listener, request.getRefreshPolicy());
                            } else if (request.getMethod() == RestRequest.Method.PUT) {
                                updateAlertingMonitorFromQueries(logIndexToQueries, detector, listener, request.getRefreshPolicy());
                            }
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
        }

        @SuppressWarnings("unchecked")
        public void importCustomRules(Detector detector, DetectorInput detectorInput, List<Pair<String, Rule>> queries, ActionListener<IndexMonitorResponse> listener) {
            final String logIndex = detectorInput.getIndices().get(0);
            List<String> ruleIds = detectorInput.getCustomRules().stream().map(DetectorRule::getId).collect(Collectors.toList());

            QueryBuilder queryBuilder = QueryBuilders.termsQuery("_id", ruleIds.toArray(new String[]{}));
            SearchRequest searchRequest = new SearchRequest(Rule.CUSTOM_RULES_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(10000));

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }

                    SearchHits hits = response.getHits();

                    try {
                        for (SearchHit hit : hits) {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );

                            Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
                            String id = hit.getId();

                            queries.add(Pair.of(id, rule));
                        }

                        Pair<String, List<Pair<String, Rule>>> logIndexToQueries = Pair.of(logIndex, queries);

                        if (request.getMethod() == RestRequest.Method.POST) {
                            createMonitorFromQueries(logIndex, queries, detector, listener, request.getRefreshPolicy());
                            // createAlertingMonitorFromQueries(logIndexToQueries, detector, listener, request.getRefreshPolicy());
                        } else if (request.getMethod() == RestRequest.Method.PUT) {
                            updateAlertingMonitorFromQueries(logIndexToQueries, detector, listener, request.getRefreshPolicy());
                        }
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

        public void indexDetector() throws IOException {
            IndexRequest indexRequest;
            if (request.getMethod() == RestRequest.Method.POST) {
                indexRequest = new IndexRequest(Detector.DETECTORS_INDEX)
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .source(request.getDetector().toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                        .timeout(indexTimeout);
            } else {
                indexRequest = new IndexRequest(Detector.DETECTORS_INDEX)
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .source(request.getDetector().toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                        .id(request.getDetectorId())
                        .timeout(indexTimeout);
            }

            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse response) {
                    Detector responseDetector = request.getDetector();
                    responseDetector.setId(response.getId());
                    onOperation(response, responseDetector);
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void onOperation(IndexResponse response, Detector detector) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(detector, null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(Detector detector, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new IndexDetectorResponse(detector.getId(), detector.getVersion(), request.getMethod() == RestRequest.Method.POST? RestStatus.CREATED: RestStatus.OK, detector);
                }
            }));
        }
    }
}