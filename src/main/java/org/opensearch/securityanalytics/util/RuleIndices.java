/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkItemResponse;
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
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class RuleIndices {

    private static final Logger log = LogManager.getLogger(RuleIndices.class);

    private final Client client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final LogTypeService logTypeService;

    public RuleIndices(LogTypeService logTypeService, Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.logTypeService = logTypeService;
    }

    public static String ruleMappings() throws IOException {
        return new String(Objects.requireNonNull(RuleIndices.class.getClassLoader().getResourceAsStream("mappings/rules.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initRuleIndex(ActionListener<CreateIndexResponse> actionListener, boolean isPrepackaged) throws IOException {
        if (!ruleIndexExists(isPrepackaged)) {
            Settings indexSettings = Settings.builder()
                    .put("index.hidden", true)
                    .build();
            CreateIndexRequest indexRequest = new CreateIndexRequest(getRuleIndex(isPrepackaged))
                    .mapping(ruleMappings())
                    .settings(indexSettings);
            client.admin().indices().create(indexRequest, actionListener);
        }
    }

    public void loadRules(List<Rule> rules, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout,
                          ActionListener<BulkResponse> actionListener, boolean isPrepackaged) throws IOException {
        String ruleIndex = getRuleIndex(isPrepackaged);
        BulkRequest bulkRequest = new BulkRequest().setRefreshPolicy(refreshPolicy).timeout(indexTimeout);

        if (rules.isEmpty()) {
            actionListener.onResponse(new BulkResponse(new BulkItemResponse[]{}, 1));
            return;
        }
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
                        updateListener,
                        false
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
                .source(new SearchSourceBuilder().size(0))
                .preference(Preference.PRIMARY_FIRST.type());
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
            logIndexToRules.put(ruleCategory, rules);
        }
        checkLogTypes(logIndexToRules, refreshPolicy, indexTimeout, listener);
    }

    private String getRuleCategory(Path folderPath) {
        return folderPath.getFileName().toString();
    }

    private void ingestQueries(Map<String, List<String>> logIndexToRules, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) throws SigmaError, IOException {
        List<Rule> queries = new ArrayList<>();

        // Moving others_cloud to the top so those queries are indexed first and can be overwritten if other categories
        // contain the same rules. Tracking issue: https://github.com/opensearch-project/security-analytics/issues/630
        List<String> categories = new ArrayList<>(logIndexToRules.keySet());
        if (categories.remove("others_cloud")) {
            categories.add(0, "others_cloud");
        }
        for (String category: categories) {
            Map<String, String> fieldMappings = logTypeService.getRuleFieldMappingsForBuiltinLogType(category);
            final QueryBackend backend = new OSQueryBackend(fieldMappings, true, true);
            queries.addAll(getQueries(backend, category, logIndexToRules.get(category)));
        }
        loadRules(queries, refreshPolicy, indexTimeout, listener, true);
    }

    private void loadQueries(String[] paths, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) throws IOException, SigmaError {
        Path path = FileUtils.getFs().getPath(paths[1]);
        loadQueries(path, refreshPolicy, indexTimeout, listener);
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

    private void checkLogTypes(Map<String, List<String>> logIndexToRules, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout, ActionListener<BulkResponse> listener) {
        logTypeService.ensureConfigIndexIsInitialized(new ActionListener<>() {
            @Override
            public void onResponse(Void unused) {
                BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                        .must(QueryBuilders.existsQuery("source"));
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(queryBuilder);
                searchSourceBuilder.fetchSource(true);
                searchSourceBuilder.size(10000);
                SearchRequest searchRequest = new SearchRequest();
                searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);
                searchRequest.source(searchSourceBuilder);

                client.search(searchRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (response.isTimedOut()) {
                            listener.onFailure(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                        }
                        try {
                            SearchHit[] hits = response.getHits().getHits();
                            Map<String, List<String>> filteredLogIndexToRules = new HashMap<>();
                            for (SearchHit hit : hits) {
                                String name = hit.getSourceAsMap().get("name").toString();

                                if (logIndexToRules.containsKey(name)) {
                                    filteredLogIndexToRules.put(name, logIndexToRules.get(name));
                                }
                            }
                            ingestQueries(filteredLogIndexToRules, refreshPolicy, indexTimeout, listener);
                        } catch (SigmaError | IOException e) {
                            onFailure(e);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                });
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }
}