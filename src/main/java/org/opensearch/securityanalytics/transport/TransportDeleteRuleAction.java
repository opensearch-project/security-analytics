/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.DeleteRuleAction;
import org.opensearch.securityanalytics.action.DeleteRuleRequest;
import org.opensearch.securityanalytics.action.DeleteRuleResponse;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportDeleteRuleAction extends HandledTransportAction<DeleteRuleRequest, DeleteRuleResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteDetectorAction.class);

    private final Client client;

    private final DetectorIndices detectorIndices;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    @Inject
    public TransportDeleteRuleAction(TransportService transportService, Client client, DetectorIndices detectorIndices, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry) {
        super(DeleteRuleAction.NAME, transportService, actionFilters, DeleteRuleRequest::new);
        this.client = client;
        this.detectorIndices = detectorIndices;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = client.threadPool();
    }

    @Override
    protected void doExecute(Task task, DeleteRuleRequest request, ActionListener<DeleteRuleResponse> listener) {
        AsyncDeleteRuleAction asyncAction = new AsyncDeleteRuleAction(task, request, listener);
        asyncAction.start();
    }

    class AsyncDeleteRuleAction {
        private final DeleteRuleRequest request;

        private final ActionListener<DeleteRuleResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final AtomicInteger checker = new AtomicInteger();
        private final Task task;

        AsyncDeleteRuleAction(Task task, DeleteRuleRequest request, ActionListener<DeleteRuleResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            String ruleId = request.getRuleId();
            GetRequest getRequest = new GetRequest(Rule.CUSTOM_RULES_INDEX, ruleId);

            client.get(getRequest, new ActionListener<>() {
                @Override
                public void onResponse(GetResponse response) {
                    if (!response.isExists()) {
                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with %s is not found", ruleId), RestStatus.NOT_FOUND));
                        return;
                    }
                    try {
                        XContentParser xcp = XContentHelper.createParser(
                            xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                            response.getSourceAsBytesRef(), XContentType.JSON);

                        Rule rule = Rule.docParse(xcp, response.getId(), response.getVersion());
                        onGetResponse(rule);
                    } catch (IOException e) {
                        onFailures(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with %s is not found", ruleId), RestStatus.NOT_FOUND));
                }
            });
        }

        private void onGetResponse(Rule rule) {
            if (detectorIndices.detectorIndexExists()) {
                QueryBuilder queryBuilder =
                        QueryBuilders.nestedQuery("detector.inputs.detector_input.custom_rules",
                                QueryBuilders.boolQuery().must(
                                        QueryBuilders.matchQuery("detector.inputs.detector_input.custom_rules.id", rule.getId())
                                ), ScoreMode.Avg);

                SearchRequest searchRequest = new SearchRequest(Detector.DETECTORS_INDEX)
                        .source(new SearchSourceBuilder()
                                .seqNoAndPrimaryTerm(true)
                                .version(true)
                                .query(queryBuilder)
                                .size(10000))
                        .preference(Preference.PRIMARY_FIRST.type());

                client.search(searchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Search request timed out. Rule with id %s cannot be deleted", rule.getId()), RestStatus.REQUEST_TIMEOUT));
                            return;
                        }

                        if (response.getHits().getTotalHits().value > 0) {
                            if (!request.isForced()) {
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with id %s is actively used by detectors. Deletion can be forced by setting forced flag to true", rule.getId()), RestStatus.BAD_REQUEST));
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
                                    if (!detector.getInputs().isEmpty()) {
                                        detector.getInputs().get(0).setCustomRules(removeRuleFromDetectors(detector, rule.getId()));
                                    }
                                    detectors.add(detector);
                                }
                            } catch (IOException ex) {
                                onFailures(ex);
                            }

                            updateDetectors(detectors);
                        } else {
                            deleteRule(rule.getId());
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
            } else {
                deleteRule(rule.getId());
            }
        }

        private void updateDetectors(List<Detector> detectors) {
            for (Detector detector: detectors) {
                IndexDetectorRequest indexRequest = new IndexDetectorRequest(detector.getId(), request.getRefreshPolicy(), RestRequest.Method.PUT, detector);
                client.execute(IndexDetectorAction.INSTANCE, indexRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexDetectorResponse response) {
                            if (response.getStatus() != RestStatus.OK) {
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Rule with id %s cannot be deleted", request.getRuleId()), RestStatus.INTERNAL_SERVER_ERROR));
                            }
                            onComplete(request.getRuleId(), detectors.size());
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
            }
        }

        private void onComplete(String ruleId, int target) {
            if (checker.incrementAndGet() == target) {
                deleteRule(ruleId);
            }
        }

        private void deleteRule(String ruleId) {
            new DeleteByQueryRequestBuilder(client, DeleteByQueryAction.INSTANCE)
                .source(Rule.CUSTOM_RULES_INDEX)
                .filter(QueryBuilders.matchQuery("_id", ruleId))
                .refresh(true)
                .execute(new ActionListener<>() {
                    @Override
                    public void onResponse(BulkByScrollResponse response) {
                        if (response.isTimedOut()) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Request timed out. Rule with id %s cannot be deleted", ruleId), RestStatus.REQUEST_TIMEOUT));
                            return;
                        }

                        onOperation(response, ruleId);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        onFailures(e);
                    }
                });
        }

        private List<DetectorRule> removeRuleFromDetectors(Detector detector, String ruleId) {
            List<DetectorRule> newRules = new ArrayList<>();
            if (!detector.getInputs().isEmpty()) {
                List<DetectorRule> rules = detector.getInputs().get(0).getCustomRules();

                for (DetectorRule rule: rules) {
                    if (!rule.getId().equals(ruleId)) {
                        newRules.add(rule);
                    }
                }
            }
            return newRules;
        }

        private void onOperation(BulkByScrollResponse response, String ruleId) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(ruleId, null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(String ruleId, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new DeleteRuleResponse(ruleId, NO_VERSION, RestStatus.NO_CONTENT);
                }
            }));
        }
    }
}