/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.MediaType;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class AutoCorrelationsRepo {

    private static String autoCorrelations() throws IOException {
        return new String(Objects.requireNonNull(AutoCorrelationsRepo.class.getClassLoader().getResourceAsStream("correlations/mitre_correlation.json")).readAllBytes(), Charset.defaultCharset());
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Set<String>> autoCorrelationsAsMap() throws IOException {
        MediaType contentType = XContentType.JSON;
        Map<String, Object> autoCorrelationData = XContentHelper.convertToMap(
                contentType.xContent(),
                autoCorrelations(),
                false
        );

        Map<String, Set<String>> autoCorrelations = new HashMap<>();
        for (Map.Entry<String, Object> autoCorrelationDataEntry: autoCorrelationData.entrySet()) {
            String intrusionSet = autoCorrelationDataEntry.getKey();
            Set<String> tags = new HashSet<>();
            if (autoCorrelationDataEntry.getValue() instanceof ArrayList) {
                List<Map<String, Object>> autoCorrelationTags = (List<Map<String, Object>>) autoCorrelationDataEntry.getValue();
                for (Map<String, Object> autoCorrelationTag: autoCorrelationTags) {
                    tags.add(autoCorrelationTag.get("mitreAttackId").toString());
                }
            }
            autoCorrelations.put(intrusionSet, tags);
        }
        return autoCorrelations;
    }

    public static Set<String> validIntrusionSets(Map<String, Set<String>> autoCorrelations, Set<String> tags) {
        Set<String> intrusionSets = new HashSet<>();
        for (Map.Entry<String, Set<String>> autoCorrelation: autoCorrelations.entrySet()) {
            for (String tag: tags) {
                if (autoCorrelation.getValue().contains(tag)) {
                    intrusionSets.add(autoCorrelation.getKey());
                }
            }
        }
        return intrusionSets;
    }
}