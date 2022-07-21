/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.threadpool.ThreadPool;

import java.util.*;

public class RuleTopicIndices {

    private static final Logger log = LogManager.getLogger(RuleTopicIndices.class);

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    public RuleTopicIndices(ClusterService clusterService, ThreadPool threadPool) {
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }

    public CreateIndexRequest prepareRuleTopicTemplateIndex(Pair<String, Map<String, Object>> ruleTopicToField) {
        String ruleTopic = ruleTopicToField.getKey();

        Map<String, Object> ruleFields = ruleTopicToField.getValue();
        ruleFields.put("query", Collections.singletonMap("type", "percolator_ext"));

        if (!ruleTopicIndexExists(ruleTopic)) {
            return new CreateIndexRequest(ruleTopic)
                .mapping(Collections.singletonMap("_doc",
                                Collections.singletonMap("properties", ruleFields)
                        )
                )
                .settings(Settings.builder().loadFromSource(
                        "{\n" +
                                "  \"index\": {\n" +
                                "    \"hidden\": true\n" +
                                "  },\n" +
                                "  \"analysis\": {\n" +
                                "    \"analyzer\": {\n" +
                                "      \"rule_analyzer\": {\n" +
                                "        \"tokenizer\": \"keyword\",\n" +
                                "        \"char_filter\": [\n" +
                                "          \"rule_ws_filter\"\n" +
                                "        ]\n" +
                                "      }\n" +
                                "    },\n" +
                                "    \"char_filter\": {\n" +
                                "      \"rule_ws_filter\": {\n" +
                                "        \"type\": \"pattern_replace\",\n" +
                                "        \"pattern\": \"(_ws_)\",\n" +
                                "        \"replacement\": \" \"\n" +
                                "      }\n" +
                                "    }\n" +
                                "  }\n" +
                                "}",
                        XContentType.JSON
                ));
        }
        return null;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }

    private Boolean ruleTopicIndexExists(String ruleTopic) {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(ruleTopic);
    }
}