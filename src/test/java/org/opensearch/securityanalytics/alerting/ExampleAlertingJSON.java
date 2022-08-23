/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting;

import org.json.JSONObject;

public class ExampleAlertingJSON {

    private ExampleAlertingJSON() {
        // do nothing (static methods/fields)
    }

    public static String within(final String key, final String json) {
        final JSONObject external = new JSONObject();
        external.put(key, new JSONObject(json));
        return external.toString(4);
    }

    public static final String SETTINGS_FLAT = "{\n" +
            "plugins.security.system_indices.enabled: true,\n" +
            "plugins.security.restapi.roles_enabled: [\"all_access\", \"security_rest_api_access\"],\n" +
            "plugins.security.system_indices.indices: [\".opendistro-alerting-config\", \".opendistro-alerting-alert*\", \".opendistro-anomaly-results*\", \".opendistro-anomaly-detector*\", \".opendistro-anomaly-checkpoints\", \".opendistro-anomaly-detection-state\", \".opendistro-reports-*\", \".opendistro-notifications-*\", \".opendistro-notebooks\", \".opendistro-asynchronous-search-response*\"]\n" +
            "}";

    public static final String SETTINGS = "{\n" +
            "  \"plugins\": {\n" +
            "    \"security\" : {\n" +
            "      \"restapi\" : {\n" +
            "        \"roles_enabled\" : [\"all_access\", \"security_rest_api_access\"]\n" +
            "        },\n" +
            "      \"system_indices\" : {\n" +
            "        \"enabled\" : true,\n" +
            "        \"indices\" : [\".opendistro-alerting-config\", \".opendistro-alerting-alert*\", \".opendistro-notifications-*\"]\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}";


    public static final String CREATE_MONITOR_1 = "{\n" +
            "  \"type\": \"monitor\",\n" +
            "  \"monitor_type\": \"doc_level_monitor\",\n" +
            "  \"name\": \"monitor-1\",\n" +
            "  \"enabled\": true,\n" +
            "  \"schedule\": {\n" +
            "    \"period\": {\n" +
            "      \"interval\": 1,\n" +
            "      \"unit\": \"MINUTES\"\n" +
            "    }\n" +
            "}\n" +
            "}";

    public static final String SEARCH_MONITOR_1 = "{\n" +
            "  \"query\": {\n" +
            "    \"match\" : {\n" +
            "      \"monitor.name\": \"test-monitor\"\n" +
            "    }\n" +
            "  }\n" +
            "}";

    public static final String CREATE_MONITOR_2 = "{\n" +
            "  \"type\": \"monitor\",\n" +
            "  \"name\": \"test-monitor\",\n" +
            "  \"monitor_type\": \"query_level_monitor\",\n" +
            "  \"enabled\": true,\n" +
            "  \"schedule\": {\n" +
            "    \"period\": {\n" +
            "      \"interval\": 1,\n" +
            "      \"unit\": \"MINUTES\"\n" +
            "    }\n" +
            "  },\n" +
            "  \"inputs\": [{\n" +
            "    \"search\": {\n" +
            "      \"indices\": [\"accounts\"],\n" +
            "      \"query\": {\n" +
            "        \"size\": 0,\n" +
            "        \"aggregations\": {},\n" +
            "        \"query\": {\n" +
            "          \"bool\": {\n" +
            "            \"filter\": {\n" +
            "              \"range\": {\n" +
            "                \"@timestamp\": {\n" +
            "                  \"gte\": \"||-1h\",\n" +
            "                  \"lte\": \"\",\n" +
            "                  \"format\": \"epoch_millis\"\n" +
            "                }\n" +
            "              }\n" +
            "            }\n" +
            "          }\n" +
            "        }\n" +
            "      }\n" +
            "    }\n" +
            "  }],\n" +
            "  \"triggers\": [{\n" +
            "    \"name\": \"test-trigger\",\n" +
            "    \"severity\": \"1\",\n" +
            "    \"condition\": {\n" +
            "      \"script\": {\n" +
            "        \"source\": \"ctx.results[0].hits.total.value > 0\",\n" +
            "        \"lang\": \"painless\"\n" +
            "      }\n" +
            "    },\n" +
            "    \"actions\": [{\n" +
            "      \"name\": \"test-action\",\n" +
            "      \"destination_id\": \"ld7912sBlQ5JUWWFThoW\",\n" +
            "      \"message_template\": {\n" +
            "        \"source\": \"This is my message body.\"\n" +
            "      },\n" +
            "      \"throttle_enabled\": true,\n" +
            "      \"throttle\": {\n" +
            "        \"value\": 27,\n" +
            "        \"unit\": \"MINUTES\"\n" +
            "      },\n" +
            "      \"subject_template\": {\n" +
            "        \"source\": \"TheSubject\"\n" +
            "      }\n" +
            "    }]\n" +
            "  }]\n" +
            "}";

}