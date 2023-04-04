package org.opensearch.securityanalytics.rules.externalsourcing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.opensearch.core.internal.io.IOUtils;
import org.opensearch.securityanalytics.rules.externalsourcing.impl.sigmahq.SigmaHQRuleSourcer;

public class GithubRepoZipDownloader {

    private static final String GITHUB_REPO_ZIP_URL_TEMPLATE = "https://api.github.com/repos/%s/%s/zipball/%s";

    private static final String TEMP_FILE_PREFIX = "opensearch-security-analytics-sigmahq-import-";
    private static final String TEMP_DIR_PREFIX = ".sigmahq-repo-";
    private String repoUrl;

    private Path zip;
    private Path unpackedArchive;

    public GithubRepoZipDownloader(String owner, String repo, String ref) {
        this.repoUrl = String.format(GITHUB_REPO_ZIP_URL_TEMPLATE, owner, repo, ref);
    }

    public Path downloadAndUnpack() throws Exception {

        Path repoZipPath = Files.createTempFile(TEMP_FILE_PREFIX, ".zip");

        downloadFile(repoUrl, repoZipPath);

        final Path target = Files.createTempDirectory(TEMP_DIR_PREFIX);

        unzip(repoZipPath, target);
        // Github repo should have single dir inside
        List<Path> dirs = Files.list(target)
                .filter(file -> Files.isDirectory(file))
                .collect(Collectors.toList());

        if (dirs.size() != 1) {
            throw new IllegalStateException("Invalid github repo. Didn't find dir inside archive!");
        }

        return target.resolve(dirs.get(0));
    }

    public boolean deleteTempFiles() {
        try {
            Files.delete(zip);
            IOUtils.rm(unpackedArchive);
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    private long downloadFile(String url, Path localPath) throws IOException {
        try (InputStream in = URI.create(url).toURL().openStream()) {
            return Files.copy(in, localPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private Path unzip(Path zip, Path target) throws Exception {
        // unzip plugin to a staging temp dir
        try (ZipInputStream zipInput = new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry entry;
            byte[] buffer = new byte[8192];
            while ((entry = zipInput.getNextEntry()) != null) {
                Path targetFile = target.resolve(entry.getName());

                // Using the entry name as a path can result in an entry outside of the plugin dir,
                // either if the name starts with the root of the filesystem, or it is a relative
                // entry like ../whatever. This check attempts to identify both cases by first
                // normalizing the path (which removes foo/..) and ensuring the normalized entry
                // is still rooted with the target plugin directory.
                if (targetFile.normalize().startsWith(target) == false) {
                    throw new Exception(
                            "Zip contains entry name '" + entry.getName() + "' resolving outside of plugin directory"
                    );
                }

                // be on the safe side: do not rely on that directories are always extracted
                // before their children (although this makes sense, but is it guaranteed?)
                if (!Files.isSymbolicLink(targetFile.getParent())) {
                    Files.createDirectories(targetFile.getParent());
                }
                if (entry.isDirectory() == false) {
                    try (OutputStream out = Files.newOutputStream(targetFile)) {
                        int len;
                        while ((len = zipInput.read(buffer)) >= 0) {
                            out.write(buffer, 0, len);
                        }
                    }
                }
                zipInput.closeEntry();
            }
        }
        return target;
    }

    public static void main(final String[] args) throws IOException {
        SigmaHQRuleSourcer s = new SigmaHQRuleSourcer();
        s.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED);
        s.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED);
    }


}
