/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

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

    public static BytesReference getBytesReference(Writeable writeable) throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();
        writeable.writeTo(out);
        BytesReference bytes = out.bytes();
        return bytes;
    }

    public static Instant getInstant(XContentParser xcp) throws IOException {
        Instant lastUpdateTime;
        if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
            lastUpdateTime = null;
        } else if (xcp.currentToken().isValue()) {
            lastUpdateTime = Instant.ofEpochMilli(xcp.longValue());
        } else {
            XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
            lastUpdateTime = null;
        }
        return lastUpdateTime;
    }

    public static void buildInstantAsField(XContentBuilder builder, Instant instant, String fieldName) throws IOException {
        if (instant == null) {
            builder.nullField(fieldName);
        } else {
            builder.timeField(fieldName, String.format(Locale.getDefault(), "%s_in_millis", fieldName), instant.toEpochMilli());
        }
    }

}