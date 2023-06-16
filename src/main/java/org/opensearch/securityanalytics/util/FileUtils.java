/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class FileUtils {

    private static FileSystem fs;

    static {
        if (fs == null || !fs.isOpen()) {
            final Map<String, String> env = new HashMap<>();
            try {
                final String url = Objects.requireNonNull(FileUtils.class.getResource("/rules")).toURI().toString();
                if (url.contains("!")) {
                    fs = FileSystems.newFileSystem(URI.create(url.split("!")[0]), env);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
        }
    }

    public static FileSystem getFs() {
        return fs;
    }
}
