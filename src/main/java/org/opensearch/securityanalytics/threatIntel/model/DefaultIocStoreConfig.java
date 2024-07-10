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
import org.opensearch.securityanalytics.commons.model.IOCType;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Model used for the default IOC store configuration
 * Stores the IOC mapping in a list of IocToIndexDetails which contains the ioc type, index pattern, and the active index
 */
public class DefaultIocStoreConfig extends IocStoreConfig implements Writeable, ToXContent {
    private static final Logger log = LogManager.getLogger(DefaultIocStoreConfig.class);
    public static final String DEFAULT_FIELD = "default";
    public static final String IOC_TO_INDEX_DETAILS_FIELD = "ioc_to_index_details";
    private final List<IocToIndexDetails> iocToIndexDetails;

    public DefaultIocStoreConfig(List<IocToIndexDetails> iocToIndexDetails) {
        this.iocToIndexDetails = iocToIndexDetails;
    }

    public DefaultIocStoreConfig(StreamInput sin) throws IOException {
        this.iocToIndexDetails = Collections.unmodifiableList(sin.readList(IocToIndexDetails::new));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(iocToIndexDetails);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject()
                .field(DEFAULT_FIELD);
        builder.startObject()
                .field(IOC_TO_INDEX_DETAILS_FIELD, iocToIndexDetails);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    public static DefaultIocStoreConfig parse(XContentParser xcp) throws IOException {
        List<IocToIndexDetails> iocToIndexDetails = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case DEFAULT_FIELD:
                    break;
                case IOC_TO_INDEX_DETAILS_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        iocToIndexDetails = null;
                    } else {
                        iocToIndexDetails = new ArrayList<>();
                        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                        while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                            iocToIndexDetails.add(IocToIndexDetails.parse(xcp));
                        }
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new DefaultIocStoreConfig(iocToIndexDetails);
    }

    @Override
    public String name() {
        return DEFAULT_FIELD;
    }

    public List<IocToIndexDetails> getIocToIndexDetails() {
        return iocToIndexDetails;
    }

    public static class IocToIndexDetails implements Writeable, ToXContent {
        public static final String IOC_TYPE_FIELD = "ioc_type";
        public static final String INDEX_PATTERN_FIELD = "index_pattern";
        public static final String ACTIVE_INDEX_FIELD = "active_index";
        private final IOCType iocType;
        private final String indexPattern;
        private final String activeIndex;

        public IocToIndexDetails(IOCType iocType, String indexPattern, String activeIndex) {
            this.iocType = iocType;
            this.indexPattern = indexPattern;
            this.activeIndex = activeIndex;
        }

        public IocToIndexDetails(StreamInput sin) throws IOException {
            this(
                    new IOCType(sin.readString()),
                    sin.readString(),
                    sin.readString()
            );
        }
        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(iocType.getType());
            out.writeString(indexPattern);
            out.writeString(activeIndex);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.startObject()
                    .field(IOC_TYPE_FIELD, iocType.getType())
                    .field(INDEX_PATTERN_FIELD, indexPattern)
                    .field(ACTIVE_INDEX_FIELD, activeIndex)
                    .endObject();
        }

        public static IocToIndexDetails parse(XContentParser xcp) throws IOException {
            IOCType iocType = null;
            String indexPattern = null;
            String activeIndex = null;

            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();

                switch (fieldName) {
                    case IOC_TYPE_FIELD:
                        iocType = toIocType(xcp.text());
                        break;
                    case INDEX_PATTERN_FIELD:
                        indexPattern = xcp.text();
                        break;
                    case ACTIVE_INDEX_FIELD:
                        activeIndex = xcp.text();
                        break;
                    default:
                        xcp.skipChildren();
                }
            }
            return new IocToIndexDetails(iocType, indexPattern, activeIndex);
        }

        public static IOCType toIocType(String name) {
            try {
                return new IOCType(name);
            } catch (IllegalArgumentException e) {
                log.error("Invalid Ioc type, cannot be parsed.", e);
                return null;
            }
        }

        public IOCType getIocType() {
            return iocType;
        }

        public String getIndexPattern() {
            return indexPattern;
        }

        public String getActiveIndex() {
            return activeIndex;
        }

    }
}
