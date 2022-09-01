/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.common.io.Streams;
import org.opensearch.common.settings.Settings;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MapperIT extends OpenSearchRestTestCase {


    @Test
    public void testMappingSuccess() throws IOException {

        String testIndexName = "my_index";

        String indexMapping =
                "    \"properties\": {" +
                "        \"netflow.event_data.SourceAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.DestinationPort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event_data.DestAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.SourcePort\": {" +
                "          \"type\": \"integer\"" +
                "        }" +
                "    }";

        createIndex(testIndexName, Settings.EMPTY, indexMapping);

        Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        request.addParameter("indexName", testIndexName);
        request.addParameter("ruleTopic", "netflow");

        Response response = client().performRequest(request);
        String responseAsText = new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    @Test
    public void testIndexNotExists() throws IOException {

        Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        request.addParameter("indexName", "myIndex");
        request.addParameter("ruleTopic", "netflow");
        try {
            client().performRequest(request);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Could not find index [myIndex]"));
        }
        /*
        String responseAsText = new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusLine().getStatusCode());
        assertTrue(responseAsText.contains("Could not find index [myIndex]"));*/
    }

}
