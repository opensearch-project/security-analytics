/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.junit.Test;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.resthandler.RestIndexTIFSourceConfigAction;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI;

public class IndexTIFSourceConfigActionTests extends OpenSearchTestCase {
    public void testIndexTIFSourceConfigActionName() {
        Assert.assertNotNull(SAIndexTIFSourceConfigAction.INSTANCE.name());
        Assert.assertEquals(SAIndexTIFSourceConfigAction.INSTANCE.name(), SAIndexTIFSourceConfigAction.NAME);
    }

    @Test
    public void testPrepareRequest_blockUrlDownloadCreate() throws Exception {
        RestIndexTIFSourceConfigAction action = new RestIndexTIFSourceConfigAction();
        NodeClient client = mock(NodeClient.class);

        String requestBody = "{\n" +
                "  \"type\": \"URL_DOWNLOAD\",\n" +
                "  \"name\": \"test\",\n" +
                "  \"format\": \"STIX2\",\n" +
                "  \"source\": {\n" +
                "    \"url_download\": {\n" +
                "      \"url\": \"http://127.0.0.1:9200\",\n" +
                "      \"feed_format\": \"csv\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"enabled_for_scan\": true,\n" +
                "  \"ioc_types\": [\"ip\"]\n" +
                "}";

        FakeRestRequest request = new FakeRestRequest.Builder(xContentRegistry())
                .withMethod(RestRequest.Method.POST)
                .withPath(THREAT_INTEL_SOURCE_URI)
                .withContent(new org.opensearch.core.common.bytes.BytesArray(requestBody),
                        org.opensearch.common.xcontent.XContentType.JSON)
                .build();

        FakeRestChannel channel = new FakeRestChannel(request, true, 1);

        action.handleRequest(request, channel, client);

        assertEquals(RestStatus.BAD_REQUEST, channel.capturedResponse().status());
        assertTrue(channel.capturedResponse().content().utf8ToString().contains("URL_DOWNLOAD"));

        verifyNoInteractions(client);
    }
}