/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.DeleteWorkflowResponse;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.action.IndexWorkflowResponse;
import org.opensearch.commons.alerting.model.BucketLevelTrigger;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.DocumentLevelTrigger;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.commons.alerting.model.SearchInput;
import org.opensearch.commons.alerting.model.Workflow;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.script.Script;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.mapper.MapperUtils;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.Value;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.MonitorService;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.WorkflowService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class TransportIndexDetectorAction extends HandledTransportAction<IndexDetectorRequest, IndexDetectorResponse> implements SecureTransportAction {

    public static final String PLUGIN_OWNER_FIELD = "security_analytics";
    private static final Logger log = LogManager.getLogger(TransportIndexDetectorAction.class);
    public static final String TIMESTAMP_FIELD_ALIAS = "timestamp";

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final DetectorIndices detectorIndices;

    private final RuleTopicIndices ruleTopicIndices;

    private final RuleIndices ruleIndices;

    private final MapperService mapperService;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final LogTypeService logTypeService;

    private volatile Boolean filterByEnabled;

    private volatile Boolean enabledWorkflowUsage;

    private final Settings settings;

    private final NamedWriteableRegistry namedWriteableRegistry;

    private final WorkflowService workflowService;

    private final MonitorService monitorService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private volatile TimeValue indexTimeout;
    @Inject
    public TransportIndexDetectorAction(TransportService transportService,
                                        Client client,
                                        ActionFilters actionFilters,
                                        NamedXContentRegistry xContentRegistry,
                                        DetectorIndices detectorIndices,
                                        RuleTopicIndices ruleTopicIndices,
                                        RuleIndices ruleIndices,
                                        MapperService mapperService,
                                        ClusterService clusterService,
                                        Settings settings,
                                        NamedWriteableRegistry namedWriteableRegistry,
                                        LogTypeService logTypeService,
                                        IndexNameExpressionResolver indexNameExpressionResolver) {
        super(IndexDetectorAction.NAME, transportService, actionFilters, IndexDetectorRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.ruleTopicIndices = ruleTopicIndices;
        this.ruleIndices = ruleIndices;
        this.mapperService = mapperService;
        this.clusterService = clusterService;
        this.settings = settings;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.logTypeService = logTypeService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.threadPool = this.detectorIndices.getThreadPool();
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.enabledWorkflowUsage = SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE.get(this.settings);
        this.monitorService = new MonitorService(client);
        this.workflowService = new WorkflowService(client, monitorService);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE, this::setEnabledWorkflowUsage);
    }

    @Override
    protected void doExecute(Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }

        checkIndicesAndExecute(task, request, listener, user);
    }

    private void checkIndicesAndExecute(
        Task task,
        IndexDetectorRequest request,
        ActionListener<IndexDetectorResponse> listener,
        User user
    ) {
        String [] detectorIndices = request.getDetector().getInputs().stream().flatMap(detectorInput -> detectorInput.getIndices().stream()).toArray(String[]::new);
        SearchRequest searchRequest =  new SearchRequest(detectorIndices)
                .source(SearchSourceBuilder.searchSource().size(1).query(QueryBuilders.matchAllQuery()))
                .preference(Preference.PRIMARY_FIRST.type());
        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                AsyncIndexDetectorsAction asyncAction = new AsyncIndexDetectorsAction(user, task, request, listener);
                asyncAction.start();
            }

            @Override
            public void onFailure(Exception e) {
                if (e instanceof OpenSearchStatusException) {
                    listener.onFailure(SecurityAnalyticsException.wrap(
                            new OpenSearchStatusException(String.format(Locale.getDefault(), "User doesn't have read permissions for one or more configured index %s", detectorIndices), RestStatus.FORBIDDEN)
                    ));
                } else if (e instanceof IndexNotFoundException) {
                    listener.onFailure(SecurityAnalyticsException.wrap(
                        new OpenSearchStatusException(String.format(Locale.getDefault(), "Indices not found %s", String.join(", ", detectorIndices)), RestStatus.NOT_FOUND)
                    ));
                }
                else {
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            }
        });
    }

    private void createMonitorFromQueries(List<Pair<String, Rule>> rulesById, Detector detector, ActionListener<List<IndexMonitorResponse>> listener, WriteRequest.RefreshPolicy refreshPolicy) throws SigmaError, IOException {
        List<Pair<String, Rule>> docLevelRules = rulesById.stream().filter(it -> !it.getRight().isAggregationRule()).collect(
            Collectors.toList());
        List<Pair<String, Rule>> bucketLevelRules = rulesById.stream().filter(it -> it.getRight().isAggregationRule()).collect(
            Collectors.toList());

        List<IndexMonitorRequest> monitorRequests = new ArrayList<>();

        if (!docLevelRules.isEmpty()) {
            monitorRequests.add(createDocLevelMonitorRequest(docLevelRules, detector, refreshPolicy, Monitor.NO_ID, Method.POST));
        }

        if (!bucketLevelRules.isEmpty()) {
            StepListener<List<IndexMonitorRequest>> bucketLevelMonitorRequests = new StepListener<>();
            buildBucketLevelMonitorRequests(bucketLevelRules, detector, refreshPolicy, Monitor.NO_ID, Method.POST, bucketLevelMonitorRequests);
            bucketLevelMonitorRequests.whenComplete(indexMonitorRequests -> {
                monitorRequests.addAll(indexMonitorRequests);
                // Do nothing if detector doesn't have any monitor
                if (monitorRequests.isEmpty()) {
                    listener.onResponse(Collections.emptyList());
                    return;
                }

                List<IndexMonitorResponse> monitorResponses = new ArrayList<>();
                StepListener<IndexMonitorResponse> addFirstMonitorStep = new StepListener();

                // Indexing monitors in two steps in order to prevent all shards failed error from alerting
                // https://github.com/opensearch-project/alerting/issues/646
                AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, monitorRequests.get(0), namedWriteableRegistry, addFirstMonitorStep);
                addFirstMonitorStep.whenComplete(addedFirstMonitorResponse -> {
                            monitorResponses.add(addedFirstMonitorResponse);

                            StepListener<List<IndexMonitorResponse>> indexMonitorsStep = new StepListener<>();
                            indexMonitorsStep.whenComplete(
                                    indexMonitorResponses -> saveWorkflow(detector, indexMonitorResponses, refreshPolicy, listener),
                                    e -> {
                                        log.error("Failed to index the workflow", e);
                                        listener.onFailure(e);
                                    });

                            int numberOfUnprocessedResponses = monitorRequests.size() - 1;
                            if (numberOfUnprocessedResponses == 0) {
                                saveWorkflow(detector, monitorResponses, refreshPolicy, listener);
                            } else {
                                // Saves the rest of the monitors and saves the workflow if supported
                                saveMonitors(
                                        monitorRequests,
                                        monitorResponses,
                                        numberOfUnprocessedResponses,
                                        indexMonitorsStep
                                );
                            }
                        },
                        listener::onFailure
                );
            }, listener::onFailure);
        } else {
            // Failure if detector doesn't have any monitor
            if (monitorRequests.isEmpty()) {
                listener.onFailure(new OpenSearchStatusException("Detector cannot be created as no compatible rules were provided", RestStatus.BAD_REQUEST));
                return;
            }

            List<IndexMonitorResponse> monitorResponses = new ArrayList<>();
            StepListener<IndexMonitorResponse> indexDocLevelMonitorStep = new StepListener();

            // Indexing monitors in two steps in order to prevent all shards failed error from alerting
            // https://github.com/opensearch-project/alerting/issues/646
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, monitorRequests.get(0), namedWriteableRegistry, indexDocLevelMonitorStep);
            indexDocLevelMonitorStep.whenComplete(addedFirstMonitorResponse -> {
                        monitorResponses.add(addedFirstMonitorResponse);
                        saveWorkflow(detector, monitorResponses, refreshPolicy, listener);
                    },
                    listener::onFailure
            );
        }
    }

    private void saveMonitors(
        List<IndexMonitorRequest> monitorRequests,
        List<IndexMonitorResponse> monitorResponses,
        int numberOfUnprocessedResponses,
        ActionListener<List<IndexMonitorResponse>> listener
    ) {
        GroupedActionListener<IndexMonitorResponse> monitorResponseListener = new GroupedActionListener(
            new ActionListener<Collection<IndexMonitorResponse>>() {
                @Override
                public void onResponse(Collection<IndexMonitorResponse> indexMonitorResponses) {
                    monitorResponses.addAll(indexMonitorResponses.stream().collect(Collectors.toList()));
                    listener.onResponse(monitorResponses);
                }
                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            }, numberOfUnprocessedResponses);

        for (int i = 1; i < monitorRequests.size(); i++) {
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, monitorRequests.get(i), namedWriteableRegistry, monitorResponseListener);
        }
    }

    /**
     * If the workflow is enabled, saves the workflow, updates the detector and returns the saved monitors
     * if not, returns the saved monitors
     * @param detector
     * @param monitorResponses
     * @param refreshPolicy
     * @param actionListener
     */
    private void saveWorkflow(
        Detector detector,
        List<IndexMonitorResponse> monitorResponses,
        RefreshPolicy refreshPolicy,
        ActionListener<List<IndexMonitorResponse>> actionListener
    ) {
        if (enabledWorkflowUsage) {
            workflowService.upsertWorkflow(
                monitorResponses,
                null,
                detector,
                refreshPolicy,
                Workflow.NO_ID,
                Method.POST,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(IndexWorkflowResponse workflowResponse) {
                            // Update passed detector with the workflowId
                            detector.setWorkflowIds(List.of(workflowResponse.getId()));
                            actionListener.onResponse(monitorResponses);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Error saving workflow", e);
                            actionListener.onFailure(e);
                        }
                    });
        } else {
            actionListener.onResponse(monitorResponses);
        }
    }

    private void updateMonitorFromQueries(String index, List<Pair<String, Rule>> rulesById, Detector detector, ActionListener<List<IndexMonitorResponse>> listener, WriteRequest.RefreshPolicy refreshPolicy) throws SigmaError, IOException {
        List<IndexMonitorRequest> monitorsToBeUpdated = new ArrayList<>();

        List<Pair<String, Rule>> bucketLevelRules = rulesById.stream().filter(it -> it.getRight().isAggregationRule()).collect(
            Collectors.toList());
        List<IndexMonitorRequest> monitorsToBeAdded = new ArrayList<>();
        // Process bucket level monitors
        if (!bucketLevelRules.isEmpty()) {
            logTypeService.getRuleFieldMappings(new ActionListener<>() {
                @Override
                public void onResponse(Map<String, Map<String, String>> ruleFieldMappings) {
                    try {
                        List<String> ruleCategories = bucketLevelRules.stream().map(Pair::getRight).map(Rule::getCategory).distinct().collect(
                                Collectors.toList());
                        Map<String, QueryBackend> queryBackendMap = new HashMap<>();
                        for (String category : ruleCategories) {
                            Map<String, String> fieldMappings = ruleFieldMappings.get(category);
                            queryBackendMap.put(category, new OSQueryBackend(fieldMappings, true, true));
                        }

                        // Pair of RuleId - MonitorId for existing monitors of the detector
                        Map<String, String> monitorPerRule = detector.getRuleIdMonitorIdMap();

                        for (Pair<String, Rule> query : bucketLevelRules) {
                            Rule rule = query.getRight();
                            if (rule.getAggregationQueries() != null) {
                                // Detect if the monitor should be added or updated
                                if (monitorPerRule.containsKey(rule.getId())) {
                                    String monitorId = monitorPerRule.get(rule.getId());
                                    monitorsToBeUpdated.add(createBucketLevelMonitorRequest(query.getRight(),
                                            detector,
                                            refreshPolicy,
                                            monitorId,
                                            Method.PUT,
                                            queryBackendMap.get(rule.getCategory())));
                                } else {
                                    monitorsToBeAdded.add(createBucketLevelMonitorRequest(query.getRight(),
                                            detector,
                                            refreshPolicy,
                                            Monitor.NO_ID,
                                            Method.POST,
                                            queryBackendMap.get(rule.getCategory())));
                                }
                            }
                        }

                        List<Pair<String, Rule>> docLevelRules = rulesById.stream().filter(it -> !it.getRight().isAggregationRule()).collect(
                                Collectors.toList());

                        // Process doc level monitors
                        if (!docLevelRules.isEmpty()) {
                            if (detector.getDocLevelMonitorId() == null) {
                                monitorsToBeAdded.add(createDocLevelMonitorRequest(docLevelRules, detector, refreshPolicy, Monitor.NO_ID, Method.POST));
                            } else {
                                monitorsToBeUpdated.add(createDocLevelMonitorRequest(docLevelRules, detector, refreshPolicy, detector.getDocLevelMonitorId(), Method.PUT));
                            }
                        }

                        List<String> monitorIdsToBeDeleted = detector.getRuleIdMonitorIdMap().values().stream().collect(Collectors.toList());
                        monitorIdsToBeDeleted.removeAll(monitorsToBeUpdated.stream().map(IndexMonitorRequest::getMonitorId).collect(
                                Collectors.toList()));

                        updateAlertingMonitors(detector, monitorsToBeAdded, monitorsToBeUpdated, monitorIdsToBeDeleted, refreshPolicy, listener);
                    } catch (IOException | SigmaError ex) {
                        listener.onFailure(ex);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            });
        } else {
            List<Pair<String, Rule>> docLevelRules = rulesById.stream().filter(it -> !it.getRight().isAggregationRule()).collect(
                    Collectors.toList());

            // Process doc level monitors
            if (!docLevelRules.isEmpty()) {
                if (detector.getDocLevelMonitorId() == null) {
                    monitorsToBeAdded.add(createDocLevelMonitorRequest(docLevelRules, detector, refreshPolicy, Monitor.NO_ID, Method.POST));
                } else {
                    monitorsToBeUpdated.add(createDocLevelMonitorRequest(docLevelRules, detector, refreshPolicy, detector.getDocLevelMonitorId(), Method.PUT));
                }
            }

            List<String> monitorIdsToBeDeleted = detector.getRuleIdMonitorIdMap().values().stream().collect(Collectors.toList());
            monitorIdsToBeDeleted.removeAll(monitorsToBeUpdated.stream().map(IndexMonitorRequest::getMonitorId).collect(
                    Collectors.toList()));

            updateAlertingMonitors(detector, monitorsToBeAdded, monitorsToBeUpdated, monitorIdsToBeDeleted, refreshPolicy, listener);
        }
    }

    /**
     *  Update list of monitors for the given detector
     *  Executed in a steps:
     *  1. Add new monitors;
     *  2. Update existing monitors;
     *  3. Updates the workflow
     *  4. Delete the monitors omitted from request
     *  5. Respond with updated list of monitors
     * @param monitorsToBeAdded Newly added monitors by the user
     * @param monitorsToBeUpdated Existing monitors that will be updated
     * @param monitorsToBeDeleted Monitors omitted by the user
     * @param refreshPolicy
     * @param listener Listener that accepts the list of updated monitors if the action was successful
     */
    private void updateAlertingMonitors(
        Detector detector,
        List<IndexMonitorRequest> monitorsToBeAdded,
        List<IndexMonitorRequest> monitorsToBeUpdated,
        List<String> monitorsToBeDeleted,
        RefreshPolicy refreshPolicy,
        ActionListener<List<IndexMonitorResponse>> listener
    ) {
        List<IndexMonitorResponse> updatedMonitors = new ArrayList<>();

        // Update monitor steps
        StepListener<List<IndexMonitorResponse>> addNewMonitorsStep = new StepListener();
        executeMonitorActionRequest(monitorsToBeAdded, addNewMonitorsStep);
        // 1. Add new alerting monitors (for the rules that didn't exist previously)
        addNewMonitorsStep.whenComplete(addNewMonitorsResponse -> {
            if (addNewMonitorsResponse != null && !addNewMonitorsResponse.isEmpty()) {
                updatedMonitors.addAll(addNewMonitorsResponse);
            }
            StepListener<List<IndexMonitorResponse>> updateMonitorsStep = new StepListener<>();
            executeMonitorActionRequest(monitorsToBeUpdated, updateMonitorsStep);
            // 2. Update existing alerting monitors (based on the common rules)
            updateMonitorsStep.whenComplete(updateMonitorResponse -> {
                    if (updateMonitorResponse != null && !updateMonitorResponse.isEmpty()) {
                        updatedMonitors.addAll(updateMonitorResponse);
                    }
                    if (detector.isWorkflowSupported() && enabledWorkflowUsage) {
                        updateWorkflowStep(
                            detector,
                            monitorsToBeDeleted,
                            refreshPolicy,
                            listener,
                            updatedMonitors,
                            addNewMonitorsResponse,
                            updateMonitorResponse
                        );
                    } else {
                        deleteMonitorStep(monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
                    }
                },
                // Handle update monitor failed (step 2)
                listener::onFailure);
            // Handle add failed (step 1)
        }, listener::onFailure);
    }

    private void deleteMonitorStep(
        List<String> monitorsToBeDeleted,
        RefreshPolicy refreshPolicy,
        List<IndexMonitorResponse> updatedMonitors,
        ActionListener<List<IndexMonitorResponse>> listener
    ) {
        monitorService.deleteAlertingMonitors(monitorsToBeDeleted,
            refreshPolicy,
            new ActionListener<>() {
                @Override
                public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                    listener.onResponse(updatedMonitors);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to delete the monitors", e);
                    listener.onFailure(e);
                }
            });
    }

    private void updateWorkflowStep(
        Detector detector,
        List<String> monitorsToBeDeleted,
        RefreshPolicy refreshPolicy,
        ActionListener<List<IndexMonitorResponse>> listener,
        List<IndexMonitorResponse> updatedMonitors,
        List<IndexMonitorResponse> addNewMonitorsResponse,
        List<IndexMonitorResponse> updateMonitorResponse
    ) {
        List<String> addedMonitorIds = addNewMonitorsResponse.stream().map(IndexMonitorResponse::getId)
            .collect(Collectors.toList());
        List<String> updatedMonitorIds = updateMonitorResponse.stream().map(IndexMonitorResponse::getId)
            .collect(Collectors.toList());

        // If there are no added or updated monitors - all monitors should be deleted
        // Before deleting the monitors, workflow should be removed so there are no monitors that are part of the workflow
        // which means that the workflow should be removed
        if (addedMonitorIds.isEmpty() && updatedMonitorIds.isEmpty()) {
            workflowService.deleteWorkflow(
                detector.getWorkflowIds().get(0),
                new ActionListener<>() {
                    @Override
                    public void onResponse(DeleteWorkflowResponse deleteWorkflowResponse) {
                        detector.setWorkflowIds(Collections.emptyList());
                        deleteMonitorStep(monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
                    }
                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to delete the workflow", e);
                        listener.onFailure(e);
                    }
                }
            );

        } else {
            // Update workflow and delete the monitors
            workflowService.upsertWorkflow(
                addNewMonitorsResponse,
                updateMonitorResponse,
                detector,
                refreshPolicy,
                detector.getWorkflowIds().get(0),
                Method.PUT,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexWorkflowResponse workflowResponse) {
                        deleteMonitorStep(monitorsToBeDeleted, refreshPolicy, updatedMonitors, listener);
                    }
                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to update the workflow");
                        listener.onFailure(e);
                    }
                });
        }
    }

    private IndexMonitorRequest createDocLevelMonitorRequest(List<Pair<String, Rule>> queries, Detector detector, WriteRequest.RefreshPolicy refreshPolicy, String monitorId, RestRequest.Method restMethod) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();

        List<DocLevelQuery> docLevelQueries = new ArrayList<>();

        for (Pair<String, Rule> query: queries) {
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
        DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(detector.getName(), detector.getInputs().get(0).getIndices(), docLevelQueries);
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

        Monitor monitor = new Monitor(monitorId, Monitor.NO_VERSION, detector.getName(), false, detector.getSchedule(), detector.getLastUpdateTime(), null,
                Monitor.MonitorType.DOC_LEVEL_MONITOR, detector.getUser(), 1, docLevelMonitorInputs, triggers, Map.of(),
                new DataSources(detector.getRuleIndex(),
                        detector.getFindingsIndex(),
                        detector.getFindingsIndexPattern(),
                        detector.getAlertsIndex(),
                        detector.getAlertsHistoryIndex(),
                        detector.getAlertsHistoryIndexPattern(),
                        DetectorMonitorConfig.getRuleIndexMappingsByType(),
                        true), PLUGIN_OWNER_FIELD);

        return new IndexMonitorRequest(monitorId, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, restMethod, monitor, null);
    }

    /**
     * Creates doc level monitor which generates per document alerts for the findings of the bucket level delegate monitors in a workflow.
     * This monitor has match all query applied to generate the alerts per each finding doc.
     */
    private IndexMonitorRequest createDocLevelMonitorMatchAllRequest(
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String monitorId,
            RestRequest.Method restMethod
    ) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();
        List<DocLevelQuery> docLevelQueries = new ArrayList<>();
        String monitorName = detector.getName() + "_chained_findings";
        String actualQuery = "_id:*";
        DocLevelQuery docLevelQuery = new DocLevelQuery(
                monitorName,
                monitorName + "doc",
                actualQuery,
                Collections.emptyList()
        );
        docLevelQueries.add(docLevelQuery);

        DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(detector.getName(), detector.getInputs().get(0).getIndices(), docLevelQueries);
        docLevelMonitorInputs.add(docLevelMonitorInput);

        List<DocumentLevelTrigger> triggers = new ArrayList<>();
        List<DetectorTrigger> detectorTriggers = detector.getTriggers();

        for (DetectorTrigger detectorTrigger : detectorTriggers) {
            String id = detectorTrigger.getId();
            String name = detectorTrigger.getName();
            String severity = detectorTrigger.getSeverity();
            List<Action> actions = detectorTrigger.getActions();
            Script condition = detectorTrigger.convertToCondition();

            triggers.add(new DocumentLevelTrigger(id, name, severity, actions, condition));
        }

        Monitor monitor = new Monitor(monitorId, Monitor.NO_VERSION, monitorName, false, detector.getSchedule(), detector.getLastUpdateTime(), null,
                Monitor.MonitorType.DOC_LEVEL_MONITOR, detector.getUser(), 1, docLevelMonitorInputs, triggers, Map.of(),
                new DataSources(detector.getRuleIndex(),
                        detector.getFindingsIndex(),
                        detector.getFindingsIndexPattern(),
                        detector.getAlertsIndex(),
                        detector.getAlertsHistoryIndex(),
                        detector.getAlertsHistoryIndexPattern(),
                        DetectorMonitorConfig.getRuleIndexMappingsByType(),
                        true), PLUGIN_OWNER_FIELD);

        return new IndexMonitorRequest(monitorId, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, restMethod, monitor, null);
    }

    private void buildBucketLevelMonitorRequests(List<Pair<String, Rule>> queries, Detector detector, WriteRequest.RefreshPolicy refreshPolicy, String monitorId, RestRequest.Method restMethod, ActionListener<List<IndexMonitorRequest>> listener) throws IOException, SigmaError {

        logTypeService.getRuleFieldMappings(new ActionListener<>() {
            @Override
            public void onResponse(Map<String, Map<String, String>> ruleFieldMappings) {
                try {
                    List<String> ruleCategories = queries.stream().map(Pair::getRight).map(Rule::getCategory).distinct().collect(
                            Collectors.toList());
                    Map<String, QueryBackend> queryBackendMap = new HashMap<>();
                    for(String category: ruleCategories) {
                        Map<String, String> fieldMappings = ruleFieldMappings.get(category);
                        queryBackendMap.put(category, new OSQueryBackend(fieldMappings, true, true));
                    }

                    List<IndexMonitorRequest> monitorRequests = new ArrayList<>();

                    for (Pair<String, Rule> query: queries) {
                        Rule rule = query.getRight();

                        // Creating bucket level monitor per each aggregation rule
                        if (rule.getAggregationQueries() != null){
                            monitorRequests.add(createBucketLevelMonitorRequest(
                                    query.getRight(),
                                    detector,
                                    refreshPolicy,
                                    Monitor.NO_ID,
                                    Method.POST,
                                    queryBackendMap.get(rule.getCategory())));
                        }
                    }
                    // if workflow usage enabled, add chained findings monitor request since there are bucket level requests
                    if(enabledWorkflowUsage && false == monitorRequests.isEmpty()) {
                        monitorRequests.add(createDocLevelMonitorMatchAllRequest(detector, RefreshPolicy.IMMEDIATE, detector.getId()+"_chained_findings", Method.POST));
                    }
                    listener.onResponse(monitorRequests);
                } catch (IOException | SigmaError ex) {
                    listener.onFailure(ex);
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    private IndexMonitorRequest createBucketLevelMonitorRequest(
            Rule rule,
            Detector detector,
            WriteRequest.RefreshPolicy refreshPolicy,
            String monitorId,
            RestRequest.Method restMethod,
            QueryBackend queryBackend
    ) throws SigmaError {

        List<String> indices = detector.getInputs().get(0).getIndices();

        AggregationQueries aggregationQueries = queryBackend.convertAggregation(rule.getAggregationItemsFromRule().get(0));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
            .seqNoAndPrimaryTerm(true)
            .version(true)
            // Build query string filter
            .query(QueryBuilders.queryStringQuery(rule.getQueries().get(0).getValue()))
            .aggregation(aggregationQueries.getAggBuilder());
        // input index can also be an index pattern or alias so we have to resolve it to concrete index
        String concreteIndex = IndexUtils.getNewIndexByCreationDate(
            clusterService.state(),
            indexNameExpressionResolver,
            indices.get(0) // taking first one is fine because we expect that all indices in list share same mappings
        );
        try {
            GetIndexMappingsResponse getIndexMappingsResponse = client.execute(
                    GetIndexMappingsAction.INSTANCE,
                    new GetIndexMappingsRequest(concreteIndex))
                .actionGet();
            MappingMetadata mappingMetadata = getIndexMappingsResponse.mappings().get(concreteIndex);
            List<Pair<String, String>> pairs = MapperUtils.getAllAliasPathPairs(mappingMetadata);
            boolean timeStampAliasPresent = pairs.
                stream()
                .anyMatch(p ->
                    TIMESTAMP_FIELD_ALIAS.equals(p.getLeft()) || TIMESTAMP_FIELD_ALIAS.equals(p.getRight()));
            if(timeStampAliasPresent) {
                BoolQueryBuilder boolQueryBuilder = searchSourceBuilder.query() == null
                    ? new BoolQueryBuilder()
                    : QueryBuilders.boolQuery().must(searchSourceBuilder.query());
                RangeQueryBuilder timeRangeFilter = QueryBuilders.rangeQuery(TIMESTAMP_FIELD_ALIAS)
                    .gt("{{period_end}}||-1h")
                    .lte("{{period_end}}")
                    .format("epoch_millis");
                boolQueryBuilder.must(timeRangeFilter);
                searchSourceBuilder.query(boolQueryBuilder);
            }
        } catch (Exception e) {
            log.error(
                String.format(Locale.getDefault(),
                    "Unable to verify presence of timestamp alias for index [%s] in detector [%s]. Not setting time range filter for bucket level monitor.",
                    concreteIndex, detector.getName()), e);
        }

        List<SearchInput> bucketLevelMonitorInputs = new ArrayList<>();
        bucketLevelMonitorInputs.add(new SearchInput(indices, searchSourceBuilder));

        List<BucketLevelTrigger> triggers = new ArrayList<>();
        BucketLevelTrigger bucketLevelTrigger = new BucketLevelTrigger(rule.getId(), rule.getTitle(), rule.getLevel(), aggregationQueries.getCondition(),
            Collections.emptyList());
        triggers.add(bucketLevelTrigger);

        /** TODO - Think how to use detector trigger
         List<DetectorTrigger> detectorTriggers = detector.getTriggers();
         for (DetectorTrigger detectorTrigger: detectorTriggers) {
         String id = detectorTrigger.getId();
         String name = detectorTrigger.getName();
         String severity = detectorTrigger.getSeverity();
         List<Action> actions = detectorTrigger.getActions();
         Script condition = detectorTrigger.convertToCondition();

         BucketLevelTrigger bucketLevelTrigger1 = new BucketLevelTrigger(id, name, severity, condition, actions);
         triggers.add(bucketLevelTrigger1);
         } **/

        Monitor monitor = new Monitor(monitorId, Monitor.NO_VERSION, detector.getName(), false, detector.getSchedule(), detector.getLastUpdateTime(), null,
            MonitorType.BUCKET_LEVEL_MONITOR, detector.getUser(), 1, bucketLevelMonitorInputs, triggers, Map.of(),
            new DataSources(detector.getRuleIndex(),
                detector.getFindingsIndex(),
                detector.getFindingsIndexPattern(),
                detector.getAlertsIndex(),
                detector.getAlertsHistoryIndex(),
                detector.getAlertsHistoryIndexPattern(),
                DetectorMonitorConfig.getRuleIndexMappingsByType(),
                true), PLUGIN_OWNER_FIELD);

        return new IndexMonitorRequest(monitorId, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, restMethod, monitor, null);
    }

    /**
     * Executes monitor related requests (PUT/POST) - returns the response once all the executions are completed
     * @param indexMonitors  Monitors to be updated/added
     * @param listener actionListener for handling updating/creating monitors
     */
    public void executeMonitorActionRequest(
        List<IndexMonitorRequest> indexMonitors,
        ActionListener<List<IndexMonitorResponse>> listener) {

        // In the case of not provided monitors, just return empty list
        if (indexMonitors == null || indexMonitors.isEmpty()) {
            listener.onResponse(new ArrayList<>());
            return;
        }

        GroupedActionListener<IndexMonitorResponse> monitorResponseListener = new GroupedActionListener(
            new ActionListener<Collection<IndexMonitorResponse>>() {
                @Override
                public void onResponse(Collection<IndexMonitorResponse> indexMonitorResponse) {
                    listener.onResponse(indexMonitorResponse.stream().collect(Collectors.toList()));
                }
                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            }, indexMonitors.size());

        // Persist monitors sequentially
        for (IndexMonitorRequest req: indexMonitors) {
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, req, namedWriteableRegistry, monitorResponseListener);
        }
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
        private final User user;

        AsyncIndexDetectorsAction(User user, Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.user = user;

            this.response = new AtomicReference<>();
        }

        void start() {
            TransportIndexDetectorAction.this.threadPool.getThreadContext().stashContext();

            logTypeService.doesLogTypeExist(request.getDetector().getDetectorType().toLowerCase(Locale.ROOT), new ActionListener<>() {
                @Override
                public void onResponse(Boolean exist) {
                    if (exist) {
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
                    } else {
                        onFailures(new OpenSearchStatusException(String.format("Detector cannot be created as logtype %s does not exist",
                                request.getDetector().getDetectorType().toLowerCase(Locale.ROOT)), RestStatus.BAD_REQUEST));
                    }
                }

                @Override
                public void onFailure(Exception e) {

                }
            });

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

            User originalContextUser = this.user;
            log.debug("user from original context is {}", originalContextUser);
            request.getDetector().setUser(originalContextUser);


            if (!detector.getInputs().isEmpty()) {
                try {
                    ruleTopicIndices.initRuleTopicIndexTemplate(new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse acknowledgedResponse) {

                            initRuleIndexAndImportRules(request, new ActionListener<>() {
                                @Override
                                public void onResponse(List<IndexMonitorResponse> monitorResponses) {
                                    request.getDetector().setMonitorIds(getMonitorIds(monitorResponses));
                                    request.getDetector().setRuleIdMonitorIdMap(mapMonitorIds(monitorResponses));
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

            User originalContextUser = this.user;
            log.debug("user from original context is {}", originalContextUser);

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

                        // security is enabled and filterby is enabled
                        if (!checkUserPermissionsWithResource(
                            originalContextUser,
                            detector.getUser(),
                            "detector",
                            detector.getId(),
                            TransportIndexDetectorAction.this.filterByEnabled
                        )

                        ) {
                            onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN)));
                            return;
                        }
                        onGetResponse(detector, detector.getUser());
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

        void onGetResponse(Detector currentDetector, User user) {
            if (request.getDetector().getEnabled() && currentDetector.getEnabled()) {
                request.getDetector().setEnabledTime(currentDetector.getEnabledTime());
            }
            request.getDetector().setMonitorIds(currentDetector.getMonitorIds());
            request.getDetector().setRuleIdMonitorIdMap(currentDetector.getRuleIdMonitorIdMap());
            request.getDetector().setWorkflowIds(currentDetector.getWorkflowIds());
            Detector detector = request.getDetector();

            String ruleTopic = detector.getDetectorType();

            log.debug("user in update detector {}", user);


            request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndexPattern(DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            request.getDetector().setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            request.getDetector().setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));
            request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));
            request.getDetector().setUser(user);

            if (!detector.getInputs().isEmpty()) {
                try {
                    ruleTopicIndices.initRuleTopicIndexTemplate(new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                            initRuleIndexAndImportRules(request, new ActionListener<>() {
                                @Override
                                public void onResponse(List<IndexMonitorResponse> monitorResponses) {
                                    request.getDetector().setMonitorIds(getMonitorIds(monitorResponses));
                                    request.getDetector().setRuleIdMonitorIdMap(mapMonitorIds(monitorResponses));
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

        public void initRuleIndexAndImportRules(IndexDetectorRequest request, ActionListener<List<IndexMonitorResponse>> listener) {
            ruleIndices.initPrepackagedRulesIndex(
                new ActionListener<>() {
                    @Override
                    public void onResponse(CreateIndexResponse response) {
                        ruleIndices.onCreateMappingsResponse(response, true);
                        ruleIndices.importRules(RefreshPolicy.IMMEDIATE, indexTimeout,
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
        public void importRules(IndexDetectorRequest request, ActionListener<List<IndexMonitorResponse>> listener) {
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
                            .size(10000))
                    .preference(Preference.PRIMARY_FIRST.type());

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
                            onFailures(new OpenSearchStatusException("Custom Rule Index not found", RestStatus.NOT_FOUND));
                        } else {
                            if (request.getMethod() == RestRequest.Method.POST) {
                                createMonitorFromQueries(queries, detector, listener, request.getRefreshPolicy());
                            } else if (request.getMethod() == RestRequest.Method.PUT) {
                                updateMonitorFromQueries(logIndex, queries, detector, listener, request.getRefreshPolicy());
                            }
                        }
                    } catch (IOException | SigmaError e) {
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
        public void importCustomRules(Detector detector, DetectorInput detectorInput, List<Pair<String, Rule>> queries, ActionListener<List<IndexMonitorResponse>> listener) {
            final String logIndex = detectorInput.getIndices().get(0);
            List<String> ruleIds = detectorInput.getCustomRules().stream().map(DetectorRule::getId).collect(Collectors.toList());

            QueryBuilder queryBuilder = QueryBuilders.termsQuery("_id", ruleIds.toArray(new String[]{}));
            SearchRequest searchRequest = new SearchRequest(Rule.CUSTOM_RULES_INDEX)
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

                        if (request.getMethod() == RestRequest.Method.POST) {
                            createMonitorFromQueries(queries, detector, listener, request.getRefreshPolicy());
                        } else if (request.getMethod() == RestRequest.Method.PUT) {
                            updateMonitorFromQueries(logIndex, queries, detector, listener, request.getRefreshPolicy());
                        }
                    } catch (IOException | SigmaError ex) {
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
                    // Revert the workflow and monitors created in previous steps
                    workflowService.deleteWorkflow(request.getDetector().getWorkflowIds().get(0),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(DeleteWorkflowResponse deleteWorkflowResponse) {
                                monitorService.deleteAlertingMonitors(request.getDetector().getMonitorIds(),
                                    request.getRefreshPolicy(),
                                    new ActionListener<>() {
                                        @Override
                                        public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                                            onFailures(e);
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
                    log.error("exception:", t);
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new IndexDetectorResponse(detector.getId(), detector.getVersion(), request.getMethod() == RestRequest.Method.POST? RestStatus.CREATED: RestStatus.OK, detector);
                }
            }));
        }

        private List<String> getMonitorIds(List<IndexMonitorResponse> monitorResponses) {
            return monitorResponses.stream().map(IndexMonitorResponse::getId).collect(
                Collectors.toList());
        }

        /**
         * Creates a map of monitor ids. In the case of bucket level monitors pairs are: RuleId - MonitorId
         * In the case of doc level monitor pair is DOC_LEVEL_MONITOR(value) - MonitorId
         * @param monitorResponses index monitor responses
         * @return map of monitor ids
         */
        private Map<String, String> mapMonitorIds(List<IndexMonitorResponse> monitorResponses) {
            return monitorResponses.stream().collect(
                Collectors.toMap(
                    // In the case of bucket level monitors rule id is trigger id
                    it -> {
                        if (MonitorType.BUCKET_LEVEL_MONITOR == it.getMonitor().getMonitorType()) {
                            return it.getMonitor().getTriggers().get(0).getId();
                        } else {
                            if (it.getMonitor().getName().contains("_chained_findings")) {
                                return "chained_findings_monitor";
                            } else {
                                return Detector.DOC_LEVEL_MONITOR;
                            }
                        }
                    },
                    IndexMonitorResponse::getId
                )
            );
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

    private void setEnabledWorkflowUsage(boolean enabledWorkflowUsage) {
        this.enabledWorkflowUsage = enabledWorkflowUsage;
    }
}
