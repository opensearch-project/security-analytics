package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.util.Map;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;

public class XContentUtils {

    public static String parseMapToJsonString(Map<String, Object> map) throws IOException {
        XContentBuilder builder = XContentFactory.contentBuilder(XContentType.JSON);
        builder.map(map);
        return XContentHelper.convertToJson(
                BytesReference.bytes(builder),
                false,
                false,
                builder.contentType()
        );
    }

}
