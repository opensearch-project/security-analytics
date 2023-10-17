/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;

/**
 * Model for threat intel feed data stored in system index.
 */
public class ThreatIntelFeedData implements Writeable, ToXContentObject {
    private static final Logger log = LogManager.getLogger(ThreatIntelFeedData.class);
    private static final String FEED_TYPE = "feed";
    private static final String TYPE_FIELD = "type";
    private static final String IOC_TYPE_FIELD = "ioc_type";
    private static final String IOC_VALUE_FIELD = "ioc_value";
    private static final String FEED_ID_FIELD = "feed_id";
    private static final String TIMESTAMP_FIELD = "timestamp";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            ThreatIntelFeedData.class,
            new ParseField(FEED_TYPE),
            xcp -> parse(xcp, null, null)
    );

    private final String iocType;
    private final String iocValue;
    private final String feedId;
    private final Instant timestamp;
    private final String type;

    public ThreatIntelFeedData(String iocType, String iocValue, String feedId, Instant timestamp) {
        this.type = FEED_TYPE;

        this.iocType = iocType;
        this.iocValue = iocValue;
        this.feedId = feedId;
        this.timestamp = timestamp;
    }

    public static ThreatIntelFeedData parse(XContentParser xcp, String id, Long version) throws IOException {
        String iocType = null;
        String iocValue = null;
        String feedId = null;
        Instant timestamp = null;
        xcp.nextToken();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IOC_TYPE_FIELD:
                    iocType = xcp.text();
                    break;
                case IOC_VALUE_FIELD:
                    iocValue = xcp.text();
                    break;
                case FEED_ID_FIELD:
                    feedId = xcp.text();
                    break;
                case TIMESTAMP_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        timestamp = null;
                    } else if (xcp.currentToken().isValue()) {
                        timestamp = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        timestamp = null;
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new ThreatIntelFeedData(iocType, iocValue, feedId, timestamp);
    }

    public String getIocType() {
        return iocType;
    }

    public String getIocValue() {
        return iocValue;
    }

    public String getFeedId() {
        return feedId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }


    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(iocType);
        out.writeString(iocValue);
        out.writeString(feedId);
        out.writeInstant(timestamp);
    }

    public ThreatIntelFeedData(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readInstant()
        );
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params);

    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        if (params.paramAsBoolean("with_type", false)) {
            builder.startObject(type);
        }
        builder.field(TYPE_FIELD, type);
        builder
                .field(IOC_TYPE_FIELD, iocType)
                .field(IOC_VALUE_FIELD, iocValue)
                .field(FEED_ID_FIELD, feedId)
                .timeField(TIMESTAMP_FIELD, String.format(Locale.getDefault(), "%s_in_millis", TIMESTAMP_FIELD), timestamp.toEpochMilli());

        return builder.endObject();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ThreatIntelFeedData tif = (ThreatIntelFeedData) o;
        return Objects.equals(iocType, tif.iocType) && Objects.equals(iocValue, tif.iocValue) && Objects.equals(feedId, tif.feedId);
    }

    @Override
    public int hashCode() {
        return Objects.hash();
    }
}
