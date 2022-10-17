/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class DetectorUtils {

    public static List<Detector> getDetectors(SearchResponse response, NamedXContentRegistry xContentRegistry) throws IOException {
        List<Detector> detectors = new LinkedList<>();
        for (SearchHit hit : response.getHits()) {
            XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry,
                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
            Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
            detectors.add(detector);
        }
        return detectors;
    }
}