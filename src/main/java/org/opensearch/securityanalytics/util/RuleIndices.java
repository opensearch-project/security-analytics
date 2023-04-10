/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.health.ClusterIndexHealth;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.mapper.MapperUtils;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.opensearch.securityanalytics.model.Detector.NO_ID;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class RuleIndices {

    private static final Logger log = LogManager.getLogger(RuleIndices.class);

    private final Client client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private static FileSystem fs;

    public RuleIndices(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    public static String ruleMappings() throws IOException {
        return new String(Objects.requireNonNull(RuleIndices.class.getClassLoader().getResourceAsStream("mappings/rules.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initRuleIndex(ActionListener<CreateIndexResponse> actionListener, boolean isPrepackaged) throws IOException {
        if (!ruleIndexExists(isPrepackaged)) {
            CreateIndexRequest indexRequest = new CreateIndexRequest(getRuleIndex(isPrepackaged))
                    .mapping(ruleMappings())
                    .settings(Settings.builder().put("index.hidden", true).build());
            client.admin().indices().create(indexRequest, actionListener);
        }
    }

    public void loadRules(List<Rule> rules, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout,
                          ActionListener<BulkResponse> actionListener, boolean isPrepackaged) throws IOException {
        String ruleIndex = getRuleIndex(isPrepackaged);
        BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(refreshPolicy).timeout(indexTimeout);

        for (Rule rule: rules) {
            IndexRequest indexRequest = new IndexRequest(ruleIndex)
                    .id(rule.getId())
                    .source(rule.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                    .timeout(indexTimeout);

            bulkRequest.add(indexRequest);
        }
        client.bulk(bulkRequest, actionListener);
    }

    public boolean ruleIndexExists(boolean isPrepackaged) {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(getRuleIndex(isPrepackaged));
    }

    public ClusterIndexHealth ruleIndexHealth(boolean isPrepackaged) {
        ClusterIndexHealth indexHealth = null;

        if (ruleIndexExists(isPrepackaged)) {
            IndexRoutingTable indexRoutingTable = clusterService.state().routingTable()
                    .index(getRuleIndex(isPrepackaged));
            IndexMetadata indexMetadata = clusterService.state().metadata()
                    .index(getRuleIndex(isPrepackaged));

            indexHealth = new ClusterIndexHealth(indexMetadata, indexRoutingTable);
        }
        return indexHealth;
    }

    private String getRuleIndex(boolean isPrepackaged) {
        return isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }

    public void onCreateMappingsResponse(CreateIndexResponse response, boolean isPrepackaged) {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Created %s with mappings.", isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX));
            if (isPrepackaged) {
                IndexUtils.prePackagedRuleIndexUpdated();
            } else {
                IndexUtils.customRuleIndexUpdated();
            }
        } else {
            log.error(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged.", isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void onUpdateMappingsResponse(AcknowledgedResponse response, boolean isPrepackaged) {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Updated  %s with mappings.", isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX));
            if (isPrepackaged) {
                IndexUtils.prePackagedRuleIndexUpdated();
            } else {
                IndexUtils.customRuleIndexUpdated();
            }
        } else {
            log.error(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", isPrepackaged? Rule.PRE_PACKAGED_RULES_INDEX: Rule.CUSTOM_RULES_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void initPrepackagedRulesIndex(ActionListener<CreateIndexResponse> createListener, ActionListener<AcknowledgedResponse> updateListener, ActionListener<SearchResponse> searchListener) {
        try {
            if (!ruleIndexExists(true)) {
                initRuleIndex(createListener, true);
            } else if (!IndexUtils.prePackagedRuleIndexUpdated) {
                IndexUtils.updateIndexMapping(
                        Rule.PRE_PACKAGED_RULES_INDEX,
                        RuleIndices.ruleMappings(), clusterService.state(), client.admin().indices(),
                        updateListener
                );
            } else {
                countRules(searchListener);
            }
        } catch (IOException ex) {
            log.info(ex.getMessage());
        }
    }

    public void importRules(WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) {
        try {
            final String url = Objects.requireNonNull(getClass().getClassLoader().getResource("rules/")).toURI().toString();

            if (url.contains("!")) {
                final String[] paths = url.split("!");
                loadQueries(paths, refreshPolicy, indexTimeout, listener);
            } else {
                Path path = Path.of(url);
                loadQueries(path, refreshPolicy, indexTimeout, listener);
            }
        } catch (URISyntaxException | IOException | SigmaError ex) {
            log.info(ex.getMessage());
        }
    }

    public void deleteRules(ActionListener<BulkByScrollResponse> listener) {
        new DeleteByQueryRequestBuilder(client, DeleteByQueryAction.INSTANCE)
                .source(Rule.PRE_PACKAGED_RULES_INDEX)
                .filter(QueryBuilders.matchAllQuery())
                .execute(listener);
    }

    public void countRules(ActionListener<SearchResponse> listener) {
        SearchRequest request = new SearchRequest(Rule.PRE_PACKAGED_RULES_INDEX)
                .source(new SearchSourceBuilder().size(0));
        client.search(request, listener);
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

    private void loadQueries(Path path, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) throws IOException, SigmaError {
        Stream<Path> folder = Files.list(path);
        List<Path> folderPaths = folder.collect(Collectors.toList());
        Map<String, List<String>> logIndexToRules = new HashMap<>();

        for (Path folderPath: folderPaths) {
            List<String> rules = getRules(List.of(folderPath));
            String ruleCategory = getRuleCategory(folderPath);

            if (Arrays.stream(Detector.DetectorType.values())
                    .anyMatch(detectorType -> detectorType.getDetectorType().equals(ruleCategory))) {
                logIndexToRules.put(ruleCategory, rules);
            }
        }
        ingestQueries(logIndexToRules, refreshPolicy, indexTimeout, listener);
    }

    private String getRuleCategory(Path folderPath) {
        return folderPath.getFileName().toString();
    }

    private void ingestQueries(Map<String, List<String>> logIndexToRules, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) throws SigmaError, IOException {
        List<Rule> queries = new ArrayList<>();

        for (Map.Entry<String, List<String>> logIndexToRule: logIndexToRules.entrySet()) {
            final QueryBackend backend = new OSQueryBackend(logIndexToRule.getKey(), true, true);
            queries.addAll(getQueries(backend, logIndexToRule.getKey(), logIndexToRule.getValue()));
        }
        loadRules(queries, refreshPolicy, indexTimeout, listener, true);
    }

    private void loadQueries(String[] paths, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) throws IOException, SigmaError {
        getFS(paths[0]);
        Path path = fs.getPath(paths[1]);
        loadQueries(path, refreshPolicy, indexTimeout, listener);
    }

    private static FileSystem getFS(String path) throws IOException {
        if (fs == null || !fs.isOpen()) {
            final Map<String, String> env = new HashMap<>();
            fs = FileSystems.newFileSystem(URI.create(path), env);
        }
        return fs;
    }

    private List<Rule> getQueries(QueryBackend backend, String category, List<String> rules) throws SigmaError {
        List<Rule> queries = new ArrayList<>();
        for (String ruleStr: rules) {
            SigmaRule rule = SigmaRule.fromYaml(ruleStr, true);
            backend.resetQueryFields();
            List<Object> ruleQueries = backend.convertRule(rule);
            Set<String> queryFieldNames = backend.getQueryFields().keySet();

            Rule ruleModel = new Rule(
                    rule.getId().toString(), NO_VERSION, rule, category,
                    ruleQueries.stream().map(Object::toString).collect(Collectors.toList()),
                    new ArrayList<>(queryFieldNames),
                    ruleStr
            );
            queries.add(ruleModel);
        }
        return queries;
    }
}