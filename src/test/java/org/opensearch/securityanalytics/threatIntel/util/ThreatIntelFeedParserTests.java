package org.opensearch.securityanalytics.threatIntel.util;

import org.junit.Test;
import org.opensearch.OpenSearchException;
import org.opensearch.securityanalytics.threatIntel.model.TIFMetadata;
import org.opensearch.test.OpenSearchTestCase;

import java.net.URL;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ThreatIntelFeedParserTests extends OpenSearchTestCase {

    @Test
    public void testGetThreatIntelFeedReaderCSV_blockedUrls() {
        String[] blockedUrls = {
                "file:///etc/passwd", //fileProtocolBlocked
                "ftp://example.com/feed.csv", //ftpProtocolBlocked
                "http://127.0.0.1:9200", //loopbackBlocked
                "http://localhost:9200", //localhostBlocked
                "http://169.254.169.254/latest/meta-data/", //linkLocalBlocked
                "http://10.0.0.1/feed.csv", //siteLocalBlocked
                "http://192.168.1.1/feed.csv", //privateNetworkBlocked
                "jar:file:///tmp/test.jar!/" //jarProtocolBlocked
        };

        for (String blockedUrl : blockedUrls) {
            expectThrows(OpenSearchException.class,
                    () -> ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(new URL(blockedUrl)));
        }
    }

    @Test
    public void testGetThreatIntelFeedReaderCSV_tifMetadata_blockedUrls() {
        String[] blockedUrls = {
                "file:///etc/passwd",
                "http://127.0.0.1:9200",
                "http://localhost:9200",
                "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.1/feed.csv",
                "http://192.168.1.1/feed.csv"
        };

        for (String blockedUrl : blockedUrls) {
            TIFMetadata tifMetadata = mock(TIFMetadata.class);
            when(tifMetadata.getUrl()).thenReturn(blockedUrl);
            expectThrows(OpenSearchException.class,
                    () -> ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata));
        }
    }
}
