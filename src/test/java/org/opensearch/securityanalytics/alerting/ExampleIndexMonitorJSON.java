/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting;

import org.json.JSONObject;

public class ExampleIndexMonitorJSON {

    public static String exampleIndexMonitor = "{\n" +
            "  \"type\": \"monitor\",\n" +
            "  \"monitor_type\": \"doc_level_monitor\",\n" +
            "  \"name\": \"Example document-level monitor\",\n" +
            "  \"enabled\": true,\n" +
            "  \"schedule\": {\n" +
            "    \"period\": {\n" +
            "      \"interval\": 1,\n" +
            "      \"unit\": \"MINUTES\"\n" +
            "    }\n" +
            "  },\n" +
            "  \"inputs\": [\n" +
            "    {\n" +
            "        \"description\": \"Example document-level monitor for audit logs\",\n" +
            "        \"indices\": [\n" +
            "          \"audit-logs\"\n" +
            "        ],\n" +
            "        \"queries\": [\n" +
            "        {\n" +
            "            \"id\": \"nKQnFYABit3BxjGfiOXC\",\n" +
            "            \"name\": \"sigma-123\",\n" +
            "            \"query\": \"region:\\\"us-west-2\\\"\",\n" +
            "            \"tags\": [\n" +
            "                \"tag1\"\n" +
            "            ]\n" +
            "        },\n" +
            "        {\n" +
            "            \"id\": \"gKQnABEJit3BxjGfiOXC\",\n" +
            "            \"name\": \"sigma-456\",\n" +
            "            \"query\": \"region:\\\"us-east-1\\\"\",\n" +
            "            \"tags\": [\n" +
            "                \"tag2\"\n" +
            "            ]\n" +
            "        },\n" +
            "        {\n" +
            "            \"id\": \"h4J2ABEFNW3vxjGfiOXC\",\n" +
            "            \"name\": \"sigma-789\",\n" +
            "            \"query\": \"message:\\\"This is a SEPARATE error from IAD region\\\"\",\n" +
            "            \"tags\": [\n" +
            "                \"tag3\"\n" +
            "            ]\n" +
            "        }\n" +
            "    ]\n" +
            "    }\n" +
            "  ],\n" +
            "    \"triggers\": [ { \"document_level_trigger\": {\n" +
            "      \"name\": \"test-trigger\",\n" +
            "      \"severity\": \"1\",\n" +
            "      \"condition\": {\n" +
            "        \"script\": {\n" +
            "          \"source\": \"(query[name=sigma-123] || query[tag=tag3]) && query[name=sigma-789]\",\n" +
            "          \"lang\": \"painless\"\n" +
            "        }\n" +
            "      },\n" +
            "      \"actions\": [\n" +
            "        {\n" +
            "            \"name\": \"test-action\",\n" +
            "            \"destination_id\": \"E4o5hnsB6KjPKmHtpfCA\",\n" +
            "            \"message_template\": {\n" +
            "                \"source\": \"Monitor  just entered alert status. Please investigate the issue. Related Finding Ids: , Related Document Ids: \",\n" +
            "                \"lang\": \"mustache\"\n" +
            "            },\n" +
            "            \"action_execution_policy\": {\n" +
            "                \"action_execution_scope\": {\n" +
            "                    \"per_alert\": {\n" +
            "                        \"actionable_alerts\": []\n" +
            "                    }\n" +
            "                }\n" +
            "            },\n" +
            "            \"subject_template\": {\n" +
            "                \"source\": \"The Subject\",\n" +
            "                \"lang\": \"mustache\"\n" +
            "            }\n" +
            "         }\n" +
            "      ]\n" +
            "  }}]\n" +
            "}";
    public static JSONObject exampleIndexMonitorJSON = new JSONObject(exampleIndexMonitor);
}
