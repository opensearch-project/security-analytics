package org.opensearch.securityanalytics.rules;

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
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.extensions.AcknowledgedResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.parser.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.parser.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.parser.objects.SigmaRule;
import org.opensearch.securityanalytics.util.FileChecksumGenerator;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class RuleIndexService {

    private static final Logger log = LogManager.getLogger(RuleIndices.class);

    private final Client client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private static FileSystem fs;

    public RuleIndexService(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    public void createIndex(String indexName, ActionListener<Void> actionListener) throws IOException {
        CreateIndexRequest indexRequest = new CreateIndexRequest(indexName)
                .mapping(ruleMappings())
                .settings(Settings.builder().put("index.hidden", true).build());
        client.admin().indices().create(indexRequest, new ActionListener<CreateIndexResponse>() {
            @Override
            public void onResponse(CreateIndexResponse result) {
                actionListener.onResponse(null);
            }

            @Override
            public void onFailure(Exception e) {
                if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                    actionListener.onResponse(null);
                } else {
                    actionListener.onFailure(e);
                }
            }
        });
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

            String md5Checksum = FileChecksumGenerator.checksumString(ruleStr);

            Rule ruleModel = new Rule(
                    rule.getId().toString(), NO_VERSION, rule, category,
                    ruleQueries.stream().map(Object::toString).collect(Collectors.toList()),
                    new ArrayList<>(queryFieldNames),
                    ruleStr,
                    md5Checksum
            );
            queries.add(ruleModel);
        }
        return queries;
    }

    public void loadRules(List<Rule> rules, WriteRequest.RefreshPolicy refreshPolicy, TimeValue indexTimeout,
                          ActionListener<BulkResponse> actionListener, boolean isPrepackaged) throws IOException {
        String ruleIndex = "";//getRuleIndex(isPrepackaged);
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

    public static String ruleMappings() throws IOException {
        return new String(Objects.requireNonNull(RuleIndices.class.getClassLoader().getResourceAsStream("mappings/rules.json")).readAllBytes(), Charset.defaultCharset());
    }
}
