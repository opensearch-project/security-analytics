/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
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
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.mapper.MapperApplier;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TransportIndexDetectorAction extends HandledTransportAction<IndexDetectorRequest, IndexDetectorResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexDetectorAction.class);

    private final Client client;

    private final DetectorIndices detectorIndices;

    private final RuleTopicIndices ruleTopicIndices;

    private final MapperApplier mapperApplier;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final Settings settings;

    private volatile TimeValue indexTimeout;

    private static FileSystem fs;

    @Inject
    public TransportIndexDetectorAction(TransportService transportService, Client client, ActionFilters actionFilters, DetectorIndices detectorIndices, RuleTopicIndices ruleTopicIndices, MapperApplier mapperApplier, ClusterService clusterService, Settings settings) {
        super(IndexDetectorAction.NAME, transportService, actionFilters, IndexDetectorRequest::new);
        this.client = client;
        this.detectorIndices = detectorIndices;
        this.ruleTopicIndices = ruleTopicIndices;
        this.mapperApplier = mapperApplier;
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

    private void importRules(IndexDetectorRequest request, ActionListener<IndexMonitorResponse> listener) throws URISyntaxException, IOException, SigmaError, InterruptedException, ExecutionException {
        final Detector detector = request.getDetector();
        final WriteRequest.RefreshPolicy refreshPolicy = request.getRefreshPolicy();
        final String ruleTopic = detector.getDetectorType();
        final String logIndex = detector.getInputs().get(0).getIndices().get(0);

        final String url = Objects.requireNonNull(getClass().getClassLoader().getResource("rules/")).toURI().toString();

        if (url.contains("!")) {
            final String[] paths = url.split("!");
            loadQueries(paths, logIndex, ruleTopic, detector, listener, refreshPolicy);
        } else {
            Path path = Path.of(url);
            loadQueries(path, logIndex, ruleTopic, detector, listener, refreshPolicy);
        }
    }

    private List<String> getRules(List<Path> listOfRules) {
        List<String> rules = new ArrayList<>();

        listOfRules.forEach(path -> {
            try {
                if (Files.isDirectory(path)) {
                    rules.addAll(getRules(Files.list(path).collect(Collectors.toList())));
                } else {
                    rules.add(Files.readString(path, Charset.defaultCharset()));
                }
            } catch (IOException ex) {
                // suppress with log
                log.warn("rules cannot be parsed");
            }
        });
        return rules;
    }

    private void loadQueries(Path path, String logIndex, String ruleTopic, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) throws IOException, SigmaError, ExecutionException, InterruptedException {
        Stream<Path> folder = Files.list(path);
        folder = folder.filter(pathElem -> pathElem.endsWith(ruleTopic));

        List<Path> folderPaths = folder.collect(Collectors.toList());
        if (folderPaths.size() == 0) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "Detector Type %s not found", ruleTopic));
        }
        Path folderPath = folderPaths.get(0);

        List<String> rules = getRules(List.of(folderPath));
        Pair<String, List<String>> logIndexToRules = Pair.of(logIndex, rules);
        ingestQueries(logIndexToRules, ruleTopic, detector, listener, refreshPolicy);
    }

    private void ingestQueries(Pair<String, List<String>> logIndexToRule, String ruleTopic, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) throws SigmaError, IOException {
        final QueryBackend backend = new OSQueryBackend(ruleTopic, true, true);

        List<Object> queries = getQueries(backend, logIndexToRule.getValue());

        Pair<String, List<Object>> logIndexToQueries = Pair.of(logIndexToRule.getKey(), queries);
        Pair<String, Map<String, Object>> logIndexToQueryFields = Pair.of(logIndexToRule.getKey(), backend.getQueryFields());

        createAlertingMonitorFromQueries(logIndexToQueries, logIndexToQueryFields, detector, listener, refreshPolicy);
    }

    private void loadQueries(String[] paths, String logIndex, String ruleTopic, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) throws IOException, SigmaError, ExecutionException, InterruptedException {
        getFS(paths[0]);
        Path path = fs.getPath(paths[1]);
        loadQueries(path, logIndex, ruleTopic, detector, listener, refreshPolicy);
    }

    private static FileSystem getFS(String path) throws IOException {
        if (fs == null || !fs.isOpen()) {
            final Map<String, String> env = new HashMap<>();
            fs = FileSystems.newFileSystem(URI.create(path), env);
        }
        return fs;
    }

    private List<Object> getQueries(QueryBackend backend, List<String> rules) throws SigmaError {
        List<Object> queries = new ArrayList<>();
        for (String ruleStr: rules) {
            SigmaRule rule = SigmaRule.fromYaml(ruleStr, true);
            List<Object> ruleQueries = backend.convertRule(rule);
            queries.addAll(ruleQueries);
        }
        return queries;
    }

    private void createAlertingMonitorFromQueries(Pair<String, List<Object>> logIndexToQueries, Pair<String, Map<String, Object>> logIndexToQueryFields, Detector detector, ActionListener<IndexMonitorResponse> listener, WriteRequest.RefreshPolicy refreshPolicy) {
        try {
            List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();

            List<DocLevelQuery> docLevelQueries = new ArrayList<>();
            int idx = 1;

            for (Object query: logIndexToQueries.getRight()) {
                DocLevelQuery docLevelQuery = new DocLevelQuery(String.valueOf(idx), String.valueOf(idx), query.toString(), List.of());
                docLevelQueries.add(docLevelQuery);

                ++idx;
            }
            DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(detector.getName(), List.of(logIndexToQueries.getKey()), docLevelQueries);
            docLevelMonitorInputs.add(docLevelMonitorInput);

            Monitor monitor = new Monitor(Monitor.NO_ID, Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
                    Monitor.MonitorType.DOC_LEVEL_MONITOR, detector.getUser(), 1, docLevelMonitorInputs, List.of(), Map.of(),
                    new DataSources(detector.getRuleIndex(),
                            detector.getFindingIndex(),
                            detector.getAlertIndex(),
                            DetectorMonitorConfig.getRuleIndexMappingsByType(detector.getDetectorType())));

            IndexMonitorRequest indexMonitorRequest = new IndexMonitorRequest(Monitor.NO_ID, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, RestRequest.Method.POST, monitor);
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, indexMonitorRequest, listener);
        } catch (Exception ex) {
            log.info(ex.getMessage());
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
            Detector detector = request.getDetector();

            String ruleTopic = detector.getDetectorType();
            if (!detector.getInputs().isEmpty()) {
                String logIndex = detector.getInputs().get(0).getIndices().get(0);

                mapperApplier.createMappingAction(logIndex, ruleTopic, true,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse response) {
                            if (response.isAcknowledged()) {
                                log.info(String.format(Locale.getDefault(), "Updated  %s with mappings.", logIndex));

                                try {
                                    ruleTopicIndices.initRuleTopicIndex(detector.getRuleIndex(), new ActionListener<>() {
                                        @Override
                                        public void onResponse(CreateIndexResponse createIndexResponse) {
                                            try {
                                                importRules(request, new ActionListener<>() {
                                                    @Override
                                                    public void onResponse(IndexMonitorResponse indexMonitorResponse) {
                                                        log.info("hit from security-analytics: call successful " + indexMonitorResponse.getId());
                                                        request.getDetector().setMonitorId(indexMonitorResponse.getId());
                                                        try {
                                                            indexDetector();
                                                        } catch (IOException e) {
                                                            onFailures(e);
                                                        }
                                                    }

                                                    @Override
                                                    public void onFailure(Exception e) {
                                                        log.info("hit from security-analytics: call failed " + e.getMessage());
                                                        onFailures(e);
                                                    }
                                                });
                                            } catch (URISyntaxException | IOException | SigmaError | InterruptedException | ExecutionException e) {
                                                onFailures(e);
                                            }
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            onFailures(e);
                                        }
                                    });
                                } catch (IOException e) {
                                    onFailures(e);
                                }
                            } else {
                                log.error(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", logIndex));
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", logIndex), RestStatus.INTERNAL_SERVER_ERROR));
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    }
                );
            }
        }

        public void indexDetector() throws IOException {
            IndexRequest indexRequest = new IndexRequest(Detector.DETECTORS_INDEX)
                    .setRefreshPolicy(request.getRefreshPolicy())
                    .source(request.getDetector().toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                    .timeout(indexTimeout);

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
                    return new IndexDetectorResponse(detector.getId(), detector.getVersion(), RestStatus.CREATED, detector);
                }
            }));
        }
    }
}