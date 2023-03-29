package org.opensearch.securityanalytics.rules.externalsourcing.impl.sigmahq;

import java.io.IOException;
import java.nio.file.Path;
import org.opensearch.securityanalytics.rules.externalsourcing.ExternalRuleSourcer;
import org.opensearch.securityanalytics.rules.externalsourcing.GithubRepoZipDownloader;
import org.opensearch.securityanalytics.rules.externalsourcing.RuleImportOptions;

public class SigmaHQRuleSourcer implements ExternalRuleSourcer {

    private static final String OWNER = "SigmaHQ";
    private static final String REPO = "sigma";
    private static final String REF = "master";

    private final GithubRepoZipDownloader githubRepoZipDownloader;

    public SigmaHQRuleSourcer() {
        this.githubRepoZipDownloader = new GithubRepoZipDownloader(OWNER, REPO, REF);
    }

    @Override
    public void importRules(RuleImportOptions options) {
        try {
            Path unpackedArchive = githubRepoZipDownloader.downloadAndUnpack();

            Path rules = unpackedArchive.resolve("rules");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    public static void main(final String[] args) throws IOException {
        SigmaHQRuleSourcer s = new SigmaHQRuleSourcer();
        s.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED);
        s.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED);
    }
}
