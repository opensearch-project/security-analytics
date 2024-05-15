/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ThreatIntelFeedDataUtils {

    private static final Logger log = LogManager.getLogger(ThreatIntelFeedDataUtils.class);

    public static List<ThreatIntelFeedData> getTifdList(SearchResponse searchResponse, NamedXContentRegistry xContentRegistry) {
        List<ThreatIntelFeedData> list = new ArrayList<>();
        if (searchResponse.getHits().getHits().length != 0) {
            Arrays.stream(searchResponse.getHits().getHits()).forEach(hit -> {
                try {
                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                            xContentRegistry,
                            LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                    );
                    xcp.nextToken();
                    list.add(ThreatIntelFeedData.parse(xcp, hit.getId(), hit.getVersion()));
                } catch (Exception e) {
                    log.error(() -> new ParameterizedMessage(
                                    "Failed to parse Threat intel feed data doc from hit {}", hit),
                            e
                    );
                }

            });
        }
        return list;
    }
}
