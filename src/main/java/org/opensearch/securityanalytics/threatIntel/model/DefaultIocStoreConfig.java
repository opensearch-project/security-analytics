package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model used for the default IOC store configuration
 * Stores the IOC mapping in a map of string to list of strings
 */
public class DefaultIocStoreConfig extends IocStoreConfig implements Writeable, ToXContent {
    private static final Logger log = LogManager.getLogger(DefaultIocStoreConfig.class);
    public static final String DEFAULT_FIELD = "default";
    public static final String IOC_MAP = "ioc_map";

    // Maps the IOC types to the list of index/alias names
    private final Map<String, List<String>> iocMapStore;

    public DefaultIocStoreConfig(Map<String, List<String>> iocMapStore) {
        this.iocMapStore = iocMapStore;
    }

    public DefaultIocStoreConfig(StreamInput sin) throws IOException {
        this.iocMapStore = sin.readMapOfLists(StreamInput::readString, StreamInput::readString);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMapOfLists(iocMapStore, StreamOutput::writeString, StreamOutput::writeString);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject()
                .field(DEFAULT_FIELD);
        builder.startObject()
                .field(IOC_MAP, iocMapStore);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    public static DefaultIocStoreConfig parse(XContentParser xcp) throws IOException {
        Map<String, List<String>> iocMapStore = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case DEFAULT_FIELD:
                    break;
                case IOC_MAP:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        iocMapStore = null;
                    } else {
                        iocMapStore = xcp.map(HashMap::new, p -> {
                            List<String> indices = new ArrayList<>();
                            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                            while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                                indices.add(xcp.text());
                            }
                            return indices;
                        });
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new DefaultIocStoreConfig(iocMapStore);
    }

    @Override
    public String name() {
        return DEFAULT_FIELD;
    }

    public Map<String, List<String>> getIocMapStore() {
        return iocMapStore;
    }

}
