/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class ThreatIntelSourceTests extends OpenSearchTestCase {

    @Test
    public void testParseWithUrlDownloadSource_fileProtocolBlocked() {
        Pair<String, String>[] blockedUrls = new Pair[] {
                Pair.of("file:///etc/passwd", "file"),
                Pair.of("ftp://example.com/feed.csv", "ftp"),
                Pair.of("jar:file:///tmp/test.jar!/", "jar")
        };

        for (Pair<String, String> blockedUrl : blockedUrls) {
            String sourceString = "{\n" +
                    "  \"url_download\": {\n" +
                    "    \"url\": \"" + blockedUrl.getLeft() + "\",\n" +
                    "    \"feed_format\": \"csv\"\n" +
                    "  }\n" +
                    "}";
            Exception e = assertThrows(IOException.class,
                    () -> Source.parse(TestHelpers.parser(sourceString)));
            assertEquals(String.format("Unsupported protocol [%s]. Only http and https are allowed.", blockedUrl.getRight()),
                    e.getMessage());
        }
    }
}
