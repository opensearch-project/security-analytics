/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.resthandlers;

import org.json.JSONObject;
import org.opensearch.securityanalytics.Tokens;
import org.opensearch.securityanalytics.alerting.ExampleAlertingJSON;
import org.opensearch.securityanalytics.alerting.SecurityAnalyticsIntegTest;
import org.opensearch.securityanalytics.alerting.TestTools;

import java.io.IOException;
import java.util.Map;

public class IndexMonitorIT extends SecurityAnalyticsIntegTest {

    private void createIndices() {
        createIndex("accounts");
        assertTrue(indexExists("accounts"));
        index("accounts", "document", "1", Map.of("name", "alice"));
        index("accounts", "document", "2", Map.of("name", "bob"));
    }

  /*  public void testIndexMonitorViaAlerting() throws Exception {
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
    }*/

    public void testIndexMonitorViaSAP() throws Exception {
        this.createIndices();
        final String jsonString = noLog(() -> {
            try {
                return TestTools.prettyString(POST(Tokens.indexMonitor(Tokens.SAP_BASE_URI, "monitors"), ExampleAlertingJSON.CREATE_MONITOR_2).getEntity().getContent());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        final JSONObject json = new JSONObject(jsonString);
        logger.info("ENTITY RESPONSE =>\n" + json.toString(4));


        throw new Exception("END INDEX MONITOR IT!");
    }
}