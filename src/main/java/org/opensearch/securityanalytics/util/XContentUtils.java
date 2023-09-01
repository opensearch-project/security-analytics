/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.util.Map;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;

public class XContentUtils {

    public static String parseMapToJsonString(Map<String, Object> map) throws IOException {
        XContentBuilder builder = MediaTypeRegistry.JSON.contentBuilder();
        builder.map(map);
        return XContentHelper.convertToJson(
                BytesReference.bytes(builder),
                false,
                false,
                builder.contentType()
        );
    }

}