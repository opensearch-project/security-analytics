/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
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
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model.Detector.NO_ID;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportIndexRuleAction extends HandledTransportAction<IndexRuleRequest, IndexRuleResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexRuleAction.class);

    private final Client client;

    private final RuleIndices ruleIndices;

    private final DetectorIndices detectorIndices;

    private final ThreadPool threadPool;

    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    private final Settings settings;

    private volatile TimeValue indexTimeout;

    @Inject
    public TransportIndexRuleAction(TransportService transportService, Client client, ActionFilters actionFilters, ClusterService clusterService, DetectorIndices detectorIndices, RuleIndices ruleIndices, NamedXContentRegistry xContentRegistry, Settings settings) {
        super(IndexRuleAction.NAME, transportService, actionFilters, IndexRuleRequest::new);
        this.client = client;
        this.detectorIndices = detectorIndices;
        this.ruleIndices = ruleIndices;
        this.threadPool = ruleIndices.getThreadPool();
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
        this.settings = settings;

        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
    }

    @Override
    protected void doExecute(Task task, IndexRuleRequest request, ActionListener<IndexRuleResponse> listener) {
        AsyncIndexRulesAction asyncAction = new AsyncIndexRulesAction(task, request, listener);
        asyncAction.start();
    }

    class AsyncIndexRulesAction {
        private final IndexRuleRequest request;

        private final ActionListener<IndexRuleResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final AtomicInteger checker = new AtomicInteger();
        private final Task task;

        AsyncIndexRulesAction(Task task, IndexRuleRequest request, ActionListener<IndexRuleResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            TransportIndexRuleAction.this.threadPool.getThreadContext().stashContext();
            try {
                if (!ruleIndices.ruleIndexExists(false)) {
                    ruleIndices.initRuleIndex(new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            ruleIndices.onCreateMappingsResponse(response, false);
                            prepareRuleIndexing();
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    }, false);
                } else if (!IndexUtils.customRuleIndexUpdated) {
                    IndexUtils.updateIndexMapping(
                            Rule.CUSTOM_RULES_INDEX,
                            RuleIndices.ruleMappings(), clusterService.state(), client.admin().indices(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    ruleIndices.onUpdateMappingsResponse(response, false);
                                    prepareRuleIndexing();
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            }
                    );
                } else {
                    prepareRuleIndexing();
                }
            } catch (IOException ex) {
                onFailures(ex);
            }
        }

        void prepareRuleIndexing() {
            String rule = request.getRule();
            String category = request.getLogType().toLowerCase(Locale.ROOT);

            try {
                SigmaRule parsedRule = SigmaRule.fromYaml(rule, true);
                if (parsedRule.getErrors() != null && parsedRule.getErrors().size() > 0) {
                    onFailures(parsedRule.getErrors().toArray(new SigmaError[]{}));
                    return;
                }

                final QueryBackend backend = new OSQueryBackend(category, true, true);
                List<Object> queries = backend.convertRule(parsedRule);
                Set<String> queryFieldNames = backend.getQueryFields().keySet();
                Rule ruleDoc = new Rule(
                        NO_ID, NO_VERSION, parsedRule, category,
                        queries,
                        new ArrayList<>(queryFieldNames),
                        rule
                );
                indexRule(ruleDoc);
            } catch (IOException | SigmaError e) {
                onFailures(e);
            }
        }

        void indexRule(Rule rule) throws IOException {
            if (request.getMethod() == RestRequest.Method.PUT) {
                if (detectorIndices.detectorIndexExists()) {
                    searchDetectors(request.getRuleId(), new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            if (response.isTimedOut()) {
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with id %s cannot be updated", rule.getId()), RestStatus.INTERNAL_SERVER_ERROR));
                                return;
                            }

                            if (response.getHits().getTotalHits().value > 0) {
                                if (!request.isForced()) {
                                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with id %s is actively used by detectors. Update can be forced by setting forced flag to true", request.getRuleId()), RestStatus.BAD_REQUEST));
                                    return;
                                }

                                List<Detector> detectors = new ArrayList<>();
                                try {
                                    for (SearchHit hit : response.getHits()) {
                                        XContentParser xcp = XContentType.JSON.xContent().createParser(
                                                xContentRegistry,
                                                LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                                        );

                                        Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
                                        detectors.add(detector);
                                    }

                                    updateRule(rule, detectors);
                                } catch (IOException ex) {
                                    onFailures(ex);
                                }
                            } else {
                                try {
                                    updateRule(rule, List.of());
                                } catch (IOException ex) {
                                    onFailures(ex);
                                }
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                } else {
                    updateRule(rule, List.of());
                }
            } else {
                IndexRequest indexRequest = new IndexRequest(Rule.CUSTOM_RULES_INDEX)
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .source(rule.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                        .timeout(indexTimeout);

                client.index(indexRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse response) {
                        rule.setId(response.getId());
                        onOperation(response, rule);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            }
        }

        private void searchDetectors(String ruleId, ActionListener<SearchResponse> listener) {
            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery("detector.inputs.detector_input.custom_rules",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery("detector.inputs.detector_input.custom_rules.id", ruleId)
                            ), ScoreMode.Avg);

            SearchRequest searchRequest = new SearchRequest(Detector.DETECTORS_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(10000));

            client.search(searchRequest, listener);
        }

        private void updateDetectors(IndexResponse indexResponse, Rule rule, List<Detector> detectors) {
            for (Detector detector: detectors) {
                IndexDetectorRequest indexRequest = new IndexDetectorRequest(detector.getId(), request.getRefreshPolicy(), RestRequest.Method.PUT, detector);
                client.execute(IndexDetectorAction.INSTANCE, indexRequest,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndexDetectorResponse response) {
                                if (response.getStatus() != RestStatus.OK) {
                                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with id %s cannot be updated", request.getRuleId()), RestStatus.INTERNAL_SERVER_ERROR));
                                }
                                onComplete(indexResponse, rule, detectors.size());
                            }

                            @Override
                            public void onFailure(Exception e) {
                                onFailures(e);
                            }
                        });
            }
        }

        private void updateRule(Rule rule, List<Detector> detectors) throws IOException {
            IndexRequest indexRequest = new IndexRequest(Rule.CUSTOM_RULES_INDEX)
                    .setRefreshPolicy(request.getRefreshPolicy())
                    .source(rule.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                    .id(request.getRuleId())
                    .timeout(indexTimeout);

            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse response) {
                    rule.setId(response.getId());

                    if (detectors.size() > 0) {
                        updateDetectors(response, rule, detectors);
                    } else {
                        onOperation(response, rule);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void onComplete(IndexResponse response, Rule rule, int target) {
            if (checker.incrementAndGet() == target) {
                onOperation(response, rule);
            }
        }

        private void onOperation(IndexResponse response, Rule rule) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(rule);
            }
        }

        private void onFailures(Exception... t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(Rule rule, Exception... t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null && t.length > 0) {
                    if (t.length > 1) {
                        throw SecurityAnalyticsException.wrap(Arrays.asList(t));
                    } else {
                        throw SecurityAnalyticsException.wrap(t[0]);
                    }
                } else {
                    return new IndexRuleResponse(rule.getId(), rule.getVersion(), RestStatus.CREATED, rule);
                }
            }));
        }
    }
}