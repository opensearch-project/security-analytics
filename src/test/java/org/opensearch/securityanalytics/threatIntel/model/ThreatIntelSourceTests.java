/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.model;

import org.junit.Test;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class ThreatIntelSourceTests extends OpenSearchTestCase {

    @Test
    public void testParseWithS3Source() throws IOException {
        String sourceString = "{\n" +
                "    \"s3\": {\n" +
                "        \"bucket_name\": \"bucket-name\",\n" +
                "        \"object_key\": \"object-key\",\n" +
                "        \"region\": \"us-west-2\",\n" +
                "        \"role_arn\": \"arn:aws:iam::123456789012:role/test_role\"\n" +
                "    }\n" +
                "  }";
        Source source = Source.parse(TestHelpers.parser(sourceString));
        assertSame(source.getClass(), S3Source.class);
        assertEquals("bucket-name", ((S3Source) source).getBucketName());
        assertEquals("object-key", ((S3Source) source).getObjectKey());
        assertEquals("us-west-2", ((S3Source) source).getRegion());
        assertEquals("arn:aws:iam::123456789012:role/test_role", ((S3Source) source).getRoleArn());
    }

    @Test
    public void testParseWithIocUploadSource() throws IOException {
        String sourceString = "{\n" +
                "    \"ioc_upload\" : {\n" +
                "        \"iocs\": []\n" +
                "      }\n" +
                "    }";
        Source source = Source.parse(TestHelpers.parser(sourceString));
        assertSame(source.getClass(), IocUploadSource.class);
        assertTrue(((IocUploadSource) source).getIocs().isEmpty());
    }

    @Test
    public void testParseWithUrlDownloadSource() throws IOException {
        String sourceString = "{\n" +
                "    \"url_download\": {\n" +
                "        \"url\": \"https://reputation.alienvault.com/reputation.generic\",\n" +
                "        \"feed_format\": \"csv\"\n" +
                "    }\n" +
                "  }";
        Source source = Source.parse(TestHelpers.parser(sourceString));
        assertSame(source.getClass(), UrlDownloadSource.class);
        assertEquals("https://reputation.alienvault.com/reputation.generic", ((UrlDownloadSource) source).getUrl().toString());
        assertEquals("csv", ((UrlDownloadSource) source).getFeedFormat());
    }

    @Test
    public void testParseInvalidSourceField() {
        String sourceString = "{\n" +
                "    \"invalid_field\" : {\n" +
                "        \"iocs\": []\n" +
                "    }";

        SecurityAnalyticsException exception = assertThrows(SecurityAnalyticsException.class, () -> Source.parse(TestHelpers.parser(sourceString)));
        assertEquals(RestStatus.BAD_REQUEST, exception.status());
        assertTrue(exception.getMessage().contains("Unexpected input in 'source' field when reading ioc store config."));
    }
}
