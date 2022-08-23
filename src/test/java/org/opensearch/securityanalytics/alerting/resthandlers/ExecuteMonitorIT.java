/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.resthandlers;

import org.json.JSONObject;
import org.junit.Ignore;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.Tokens;
import org.opensearch.securityanalytics.alerting.ExampleAlertingJSON;
import org.opensearch.securityanalytics.alerting.SecurityAnalyticsIntegTest;
import org.opensearch.securityanalytics.alerting.TestTools;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

@Ignore
public class ExecuteMonitorIT extends SecurityAnalyticsIntegTest {

    private void createIndices() {
        createIndex("accounts");
        assertTrue(indexExists("accounts"));
        index("accounts", "document", "1", Map.of("name", "alice"));
        index("accounts", "document", "2", Map.of("name", "bob"));
    }

    public void testExecuteMonitorViaAlerting() throws Exception {
        this.createIndices();
        final String jsonString = noLog(() -> {
            try {
                return TestTools.prettyString(POST(Tokens.ALERTING_MONITORS_BASE_URI, ExampleAlertingJSON.CREATE_MONITOR_2).getEntity().getContent());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        final JSONObject json = new JSONObject(jsonString);
        logger.info("ENTITY RESPONSE =>\n" + json.toString(4));
        final String id = json.getString("_id");
        logger.info("Monitor id: " + id);
        assertEquals(RestStatus.OK.getStatus(), POST(Tokens.executeMonitor(Tokens.ALERTING_MONITORS_BASE_URI, id)).getStatusLine().getStatusCode());
    }

    public void testExecuteMonitorViaSAP() throws Exception {
        this.createIndices();
        final String jsonString = noLog(() -> {
            try {
                return TestTools.prettyString(POST(Tokens.ALERTING_MONITORS_BASE_URI, ExampleAlertingJSON.CREATE_MONITOR_2).getEntity().getContent());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        final JSONObject json = new JSONObject(jsonString);
        logger.info("ENTITY RESPONSE =>\n" + json.toString(4));
        final String id = json.getString("_id");
        logger.info("Monitor id: " + id);
        logger.info("HERE" + Arrays.toString(cluster().httpAddresses()));

        assertEquals(200, POST(Tokens.executeMonitor(Tokens.SAP_MONITORS_BASE_URI, id)).getStatusLine().getStatusCode());

        throw new RuntimeException("DEAD!");
    }
}