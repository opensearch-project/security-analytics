package org.opensearch.securityanalytics.rules.externalsourcing.impl.sigmahq;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportResponse;
import org.opensearch.securityanalytics.action.SearchRuleAction;
import org.opensearch.securityanalytics.action.SearchRuleRequest;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.externalsourcing.ExternalRuleSourcer;
import org.opensearch.securityanalytics.rules.externalsourcing.GithubRepoZipDownloader;
import org.opensearch.securityanalytics.rules.externalsourcing.RuleImportOptions;
import org.opensearch.securityanalytics.rules.parser.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.parser.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.parser.objects.SigmaRule;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.ChecksumGenerator;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class SigmaHQRuleSourcer implements ExternalRuleSourcer {

    private static final Logger log = LogManager.getLogger(SigmaHQRuleSourcer.class);

    public static final String SIGMAHQ_SOURCER_ID = "sigmahq";

    private static final String OWNER = "SigmaHQ";
    private static final String REPO = "sigma";
    private static final String REF = "master";

    private static final long MAX_FILE_SIZE = 1024 * 1024;

    private final GithubRepoZipDownloader githubRepoZipDownloader;

    private Client client;
    private NamedXContentRegistry xContentRegistry;

    private volatile TimeValue indexTimeout;

    private BulkRequest bulkRequest;

    public SigmaHQRuleSourcer(Client client, ClusterService clusterService, NamedXContentRegistry xContentRegistry) {
        this.xContentRegistry = xContentRegistry;
        this.client = client;

        this.githubRepoZipDownloader = new GithubRepoZipDownloader(OWNER, REPO, REF);

        clusterService.getClusterSettings().addSettingsUpdateConsumer(
                SecurityAnalyticsSettings.INDEX_TIMEOUT,
                newIndexTimeout -> this.indexTimeout = newIndexTimeout
        );

    }

    public String getId() {
        return SIGMAHQ_SOURCER_ID;
    }

    @Override
    public void importRules(RuleImportOptions options, ActionListener<ExternalSourceRuleImportResponse> listener) {
        try {

            bulkRequest = new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).timeout(indexTimeout);

            Path unpackedArchive = AccessController.doPrivileged(
                    (PrivilegedAction<Path>) () -> {
                        try {
                            return githubRepoZipDownloader.downloadAndUnpack();
                        } catch (Exception e) {
                            return null;
                        }
                    }
            );

            Map<String, List<RuleDescriptor>> sigmaHQRulesMap = populateAllRulesFromRepo(unpackedArchive);

            StepListener<Map<String, List<RuleDescriptor>>> getAllPrepackagedRulesListener = new StepListener<>();
            getAllPrepackagedRules(getAllPrepackagedRulesListener);
            getAllPrepackagedRulesListener.whenComplete(prepackagedRules -> {

                sigmaHQRulesMap.forEach((category, sigmaHQRules) -> {

                    try {
                        QueryBackend queryBackend = new OSQueryBackend(category, true, true);

                        List<RuleDescriptor> existingRules = prepackagedRules.get(category);
                        if (existingRules == null) {
                            return;
                        }
                        for (RuleDescriptor r : sigmaHQRules) {
                            Optional<RuleDescriptor> optExistingRule = existingRules.stream().filter(e -> e.id.equals(r.id)).findFirst();
                            if (optExistingRule.isPresent()) {
                                if (optExistingRule.get().md5Checksum.equals(r.md5Checksum) == false && options.overwriteModified()) {
                                    addUpdateRequest(
                                        createRuleModel(r, queryBackend)
                                    );
                                }
                            } else {
                                // This is new rule, so index it
                                addIndexRequest(
                                    createRuleModel(r, queryBackend)
                                );
                            }
                        }
                    } catch (Exception e) {
                        log.error(e);
                    }
                });

                // Execute all bulk actions if any
                if (bulkRequest.numberOfActions() > 0) {
                    client.bulk(
                        bulkRequest,
                        ActionListener.wrap(responses -> sendResponse(responses, listener), listener::onFailure)
                    );
                } else {
                    sendResponse(null, listener);
                }

            }, e -> {});
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void sendResponse(BulkResponse responses, ActionListener<ExternalSourceRuleImportResponse> listener) {
        int added = 0;
        int updated = 0;
        int deleted = 0;
        int failed = 0;

        if (responses == null) {
            listener.onResponse(new ExternalSourceRuleImportResponse(added, updated, deleted, failed));
            return;
        }

        for (BulkItemResponse i : responses.getItems()) {
            if (i.isFailed()) {
                failed++;
            } else if (i.getOpType() == DocWriteRequest.OpType.INDEX) {
                added++;
            } else if (i.getOpType() == DocWriteRequest.OpType.UPDATE) {
                updated++;
            } else if (i.getOpType() == DocWriteRequest.OpType.DELETE) {
                deleted++;
            }
        }
        listener.onResponse(new ExternalSourceRuleImportResponse(added, updated, deleted, failed));
    }

    private Rule createRuleModel(RuleDescriptor r, QueryBackend backend) {
        try {
            SigmaRule rule = SigmaRule.fromYaml(r.originalPayload, true);
            backend.resetQueryFields();
            List<Object> ruleQueries = backend.convertRule(rule);
            Set<String> queryFieldNames = backend.getQueryFields().keySet();

            String md5Checksum = ChecksumGenerator.checksumString(r.originalPayload);

            return new Rule(
                    rule.getId().toString(), NO_VERSION, rule, r.category,
                    ruleQueries.stream().map(Object::toString).collect(Collectors.toList()),
                    new ArrayList<>(queryFieldNames),
                    r.originalPayload, md5Checksum
            );
        } catch (Exception e) {
            log.error("Error creating Rule Model: " + e);
            return null;
        }
    }

    private void addUpdateRequest(Rule r) throws IOException {

        if (r == null) {
            return;
        }
        UpdateRequest updateRequest = new UpdateRequest(Rule.PRE_PACKAGED_RULES_INDEX, r.getId())
                .doc(r.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                .timeout(indexTimeout);

        bulkRequest.add(updateRequest);
    }

    private void addIndexRequest(Rule r) throws IOException {

        if (r == null) {
            return;
        }
        IndexRequest indexRequest = new IndexRequest(Rule.PRE_PACKAGED_RULES_INDEX)
                .id(r.getId())
                .source(r.toXContent(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                .timeout(indexTimeout);

        bulkRequest.add(indexRequest);
    }

    private void getAllPrepackagedRules(ActionListener<Map<String, List<RuleDescriptor>>> listener) {
        Map<String, List<RuleDescriptor>> ruleMap = new HashMap<>();

        searchAllRules(
                new ArrayList<>(10000),
                0,
                ActionListener.wrap(hits -> {
                        // Parse all Rule documents into RuleDescriptor map
                        for (SearchHit hit : hits) {
                            try {
                                Rule rule = Rule.docParse(hit, xContentRegistry);
                                String md5Checksum = rule.getChecksum();
                                if (md5Checksum == null) {
                                    md5Checksum = ChecksumGenerator.checksumString(rule.getRule());
                                }
                                RuleDescriptor ruleDescriptor = new RuleDescriptor(
                                        rule.getId(),
                                        rule.getRule(),
                                        md5Checksum,
                                        rule.getCategory()
                                );
                                if (ruleMap.containsKey(rule.getCategory()) == false) {
                                    List<RuleDescriptor> rules = new ArrayList<>();
                                    rules.add(ruleDescriptor);
                                    ruleMap.put(rule.getCategory(), rules);
                                } else {
                                    ruleMap.get(rule.getCategory()).add(ruleDescriptor);
                                }
                            } catch (IOException e) {
                                log.error("Failed parsing Rule from XContent: " + e.getMessage());
                            }
                        }
                        listener.onResponse(ruleMap);
                }, listener::onFailure)
        );
    }

    private void searchAllRules(List<SearchHit> allHits, int fromIndex, ActionListener<List<SearchHit>> listener) {
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.source(SearchSourceBuilder.searchSource()
                .size(10000)
                .from(fromIndex)
                .fetchSource(true)
                .query(QueryBuilders.matchAllQuery())
        ).indices(Rule.PRE_PACKAGED_RULES_INDEX);

        client.execute(
                SearchRuleAction.INSTANCE,
                new SearchRuleRequest(true, searchRequest),
                ActionListener.wrap(response -> {
                    SearchHits searchHits = response.getHits();
                    allHits.addAll(Arrays.asList((searchHits.getHits())));
                    if (searchHits.getTotalHits().value > allHits.size()) {
                        final int _fromIndex = fromIndex + searchHits.getHits().length;
                        searchAllRules(allHits, _fromIndex, listener);
                    } else {
                        listener.onResponse(allHits);
                    }
                }, listener::onFailure)
        );
    }

    public static Map<String, List<RuleDescriptor>> populateAllRulesFromRepo(Path repoDir) throws IOException {
        Map<String, List<RuleDescriptor>> ruleMap = new HashMap<>();

        SigmaHQDirMapping.ALL_CATEGORIES_MAPPING.forEach((category, mapping) -> {
            try {
                Files.walkFileTree(Paths.get(repoDir.toAbsolutePath().toString(), mapping.dirPath), new FileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        if (
                                attrs.isSymbolicLink() || attrs.isDirectory() || attrs.isOther()
                                        || attrs.size() > MAX_FILE_SIZE || mapping.isFilePassingFilters(file) == false
                        ) {
                            return FileVisitResult.CONTINUE;
                        }

                        String md5 = null;
                        try {
                            md5 = ChecksumGenerator.checksumFile(file);
                        } catch (Exception e) {
                            return FileVisitResult.CONTINUE;
                        }

                        List<RuleDescriptor> rules = null;
                        if (ruleMap.containsKey(category) == false) {
                            rules = new ArrayList<>();
                            ruleMap.put(category, rules);
                        } else {
                            rules = ruleMap.get(category);
                        }
                        String rulePayload = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                        String ruleId = null;
                        try {
                            SigmaRule r = SigmaRule.fromYaml(rulePayload, false);
                            ruleId = r.getId().toString();
                        } catch (SigmaError e) {
                            return FileVisitResult.CONTINUE;
                        }
                        rules.add(new RuleDescriptor(
                                ruleId,
                                rulePayload,
                                md5,
                                category
                        ));
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                        return FileVisitResult.CONTINUE;
                    }
                });
            } catch (IOException e) {
                //log
            }
        });
        return ruleMap;
    }

    static class RuleDescriptor {
        String id;
        String originalPayload;
        String md5Checksum;
        String category;

        public RuleDescriptor(String id, String originalPayload, String md5Checksum, String category) {
            this.id = id;
            this.originalPayload = originalPayload;
            this.md5Checksum = md5Checksum;
            this.category = category;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            RuleDescriptor that = (RuleDescriptor) o;

            return id.equals(that.id);
        }

        @Override
        public int hashCode() {
            return id.hashCode();
        }
    }

}
