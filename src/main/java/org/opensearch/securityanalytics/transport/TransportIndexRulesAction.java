/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.IndexRulesAction;
import org.opensearch.securityanalytics.action.IndexRulesRequest;
import org.opensearch.securityanalytics.action.IndexRulesResponse;
import org.opensearch.securityanalytics.mappings.MapperApplier;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.util.RestHandlerUtils;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TransportIndexRulesAction extends HandledTransportAction<IndexRulesRequest, IndexRulesResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexRulesAction.class);

    private final Client client;

    private final RuleTopicIndices ruleTopicIndices;

    private final MapperApplier mapperApplier;

    private final ThreadPool threadPool;

    private static FileSystem fs;

    @Inject
    public TransportIndexRulesAction(TransportService transportService, Client client, ActionFilters actionFilters, RuleTopicIndices ruleTopicIndices, MapperApplier mapperApplier) {
        super(IndexRulesAction.NAME, transportService, actionFilters, IndexRulesRequest::new);
        this.client = client;
        this.ruleTopicIndices = ruleTopicIndices;
        this.mapperApplier = mapperApplier;
        this.threadPool = this.ruleTopicIndices.getThreadPool();
    }

    @Override
    protected void doExecute(Task task, IndexRulesRequest request, ActionListener<IndexRulesResponse> listener) {
        AsyncIndexRulesAction asyncAction = new AsyncIndexRulesAction(task, request, listener);
        if (request.getRule().isEmpty()) {
            importRules(listener, request, asyncAction);
        } else {
            importRule(listener, request, asyncAction);
        }
    }

    private void importRule(ActionListener<IndexRulesResponse> actionListener, IndexRulesRequest request, AsyncIndexRulesAction asyncAction) {
        try {
            ingestQueries(Pair.of(request.getRuleTopic(), List.of(request.getRule())), asyncAction);
        } catch (IOException | SigmaError | InterruptedException | ExecutionException ex) {
            actionListener.onFailure(ex);
        }
    }

    private void importRules(ActionListener<IndexRulesResponse> actionListener, IndexRulesRequest request, AsyncIndexRulesAction asyncAction) {
        try {
            final String ruleTopic = request.getRuleTopic();
            final String url = Objects.requireNonNull(getClass().getClassLoader().getResource("rules/")).toURI().toString();

            if (url.contains("!")) {
                final String[] paths = url.split("!");
                loadQueries(paths, ruleTopic, asyncAction);
            } else {
                Path path = Path.of(url);
                loadQueries(path, ruleTopic, asyncAction);
            }
        } catch (URISyntaxException | IOException | SigmaError | InterruptedException | ExecutionException ex) {
            actionListener.onFailure(ex);
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

    private void loadQueries(Path path, String ruleTopic, AsyncIndexRulesAction asyncAction) throws IOException, SigmaError, ExecutionException, InterruptedException {
        Stream<Path> folder = Files.list(path);
        folder = folder.filter(pathElem -> pathElem.endsWith(ruleTopic));

        List<Path> folderPaths = folder.collect(Collectors.toList());
        if (folderPaths.size() == 0) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "%s %s not found", RestHandlerUtils.RULE_TOPIC, ruleTopic));
        }
        Path folderPath = folderPaths.get(0);

        List<String> rules = getRules(List.of(folderPath));
        String logIndex = folderPath.getFileName().toString();
        Pair<String, List<String>> logIndexToRules = Pair.of(logIndex, rules);
        ingestQueries(logIndexToRules, asyncAction);
    }

    private void ingestQueries(Pair<String, List<String>> logIndexToRule, AsyncIndexRulesAction asyncAction) throws SigmaError, ExecutionException, InterruptedException, IOException {
        final QueryBackend backend = new OSQueryBackend(true, true);

        List<Object> queries = getQueries(backend, logIndexToRule.getValue());
        long rulesCount = queries.size();

        Pair<String, List<Object>> logIndexToQueries = Pair.of(logIndexToRule.getKey(), queries);
        Pair<String, Map<String, Object>> logIndexToQueryFields = Pair.of(logIndexToRule.getKey(), backend.getQueryFields());

        asyncAction.start(logIndexToQueryFields, rulesCount);
    }

    private void loadQueries(String[] paths, String ruleTopic, AsyncIndexRulesAction asyncAction) throws IOException, SigmaError, ExecutionException, InterruptedException {
        getOrCreateFS(paths[0]);
        Path path = fs.getPath(paths[1]);
        loadQueries(path, ruleTopic, asyncAction);
    }

    private static FileSystem getOrCreateFS(String path) throws IOException {
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

    private void createAlertingMonitorFromQueries(Map<String, List<Object>> logIndexToQueries) {
        try {
        } catch (Exception ex) {
            log.info(ex.getMessage());
        }
    }

    class AsyncIndexRulesAction {
        private final IndexRulesRequest request;

        private final ActionListener<IndexRulesResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncIndexRulesAction(Task task, IndexRulesRequest request, ActionListener<IndexRulesResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start(Pair<String, Map<String, Object>> logIndexToQueryFields, long rulesCount) {
            CreateIndexRequest request = ruleTopicIndices.prepareRuleTopicTemplateIndex(logIndexToQueryFields);

            if (request != null) {
                client.admin().indices().create(request, new ActionListener<>() {
                    @Override
                    public void onResponse(CreateIndexResponse response) {
                        try {
                            client.admin().indices().putMapping(
                                    mapperApplier.createMappingAction(logIndexToQueryFields.getKey(), logIndexToQueryFields.getKey()),
                                    new ActionListener<>() {
                                        @Override
                                        public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                                            onOperation(acknowledgedResponse, rulesCount);
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
            } else {
                onOperation(null, 0);
            }
        }

        private void onOperation(AcknowledgedResponse response, long rulesCount) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(rulesCount);
            }
        }

        private void onFailures(Throwable t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(0);
            }
        }

        private void finishHim(long ruleCount) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> new IndexRulesResponse(ruleCount, RestStatus.CREATED)));
        }
    }
}