package org.opensearch.securityanalytics.rules.externalsourcing.impl.sigmahq;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.opensearch.securityanalytics.model.RuleCategory;
import org.opensearch.securityanalytics.rules.externalsourcing.ExternalRuleSourcer;
import org.opensearch.securityanalytics.rules.externalsourcing.GithubRepoZipDownloader;
import org.opensearch.securityanalytics.rules.externalsourcing.RuleImportOptions;
import org.opensearch.securityanalytics.util.FileChecksumGenerator;

public class SigmaHQRuleSourcer implements ExternalRuleSourcer {

    private static final String OWNER = "SigmaHQ";
    private static final String REPO = "sigma";
    private static final String REF = "master";

    private static final Path PREPACKAGED_RULES_PATH = Paths.get("/Users/petardzepina/opensearch-sa/security-analytics/src/main/resources/rules/");
    private static final long MAX_FILE_SIZE = 1024 * 1024;

    private final GithubRepoZipDownloader githubRepoZipDownloader;

    public SigmaHQRuleSourcer() {
        this.githubRepoZipDownloader = new GithubRepoZipDownloader(OWNER, REPO, REF);
    }

    @Override
    public void importRules(RuleImportOptions options) {
        try {
            Path unpackedArchive = githubRepoZipDownloader.downloadAndUnpack();

            Path sigmaHQRulesPath = unpackedArchive.resolve("rules/");

            String prefixToTrim = sigmaHQRulesPath.toString();

            //Map<String, String> localRulesHashes = FileChecksumGenerator.getChecksumOfAllFilesInDir(PREPACKAGED_RULES_PATH, "/rules/");
            Map<String, List<SigmaRule>> sigmaHQRulesHashes = populateAllRulesFromRepo(sigmaHQRulesPath);


            System.out.println(sigmaHQRulesHashes.size());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public static Map<String, List<SigmaRule>> populateAllRulesFromRepo(Path dir) throws IOException {
        Map<String, List<SigmaRule>> ruleMap = new HashMap<>();



        Files.walkFileTree(dir, new FileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (attrs.isSymbolicLink() || attrs.isDirectory() || attrs.isOther() || attrs.size() > MAX_FILE_SIZE) {
                    return FileVisitResult.CONTINUE;
                }
                String md5 = null;
                try {
                    md5 = FileChecksumGenerator.checksumFile(file);
                } catch (Exception e) {
                    return FileVisitResult.CONTINUE;
                }

                // Trim pa
                int categoryStartIndex = file.toString().indexOf("/rules/") + "/rules/".length();
                int categoryEndIndex = file.toString().indexOf("/", categoryStartIndex);
                String category = file.toString().substring(categoryStartIndex, categoryEndIndex);
                String normalizedPath = file.toString().substring(categoryStartIndex + 1);
                if (RuleCategory.ALL_RULE_CATEGORIES.contains(category) == false) {
                    return FileVisitResult.CONTINUE;
                }
                List<SigmaRule> rules = null;
                if (ruleMap.containsKey(category) == false) {
                    rules = new ArrayList<>();
                    ruleMap.put(category, rules);
                } else {
                    rules = ruleMap.get(category);
                }
                String rulePayload = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                rules.add(new SigmaRule(
                        rulePayload,
                        FileChecksumGenerator.checksumString(rulePayload),
                        category
                ));

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
        return ruleMap;
    }

    public static void main(final String[] args) throws IOException {
        SigmaHQRuleSourcer s = new SigmaHQRuleSourcer();
        s.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED);
        s.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED);
    }

    static class SigmaRule {
        String originalPayload;
        String md5Checksum;
        String category;

        public SigmaRule(String originalPayload, String md5Checksum, String category) {
            this.originalPayload = originalPayload;
            this.md5Checksum = md5Checksum;
            this.category = category;
        }
    }

}
