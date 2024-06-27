package org.opensearch.securityanalytics.model.threatintel;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * container class to store a tuple of feed id, ioc id and index.
 */
public class IocWithFeeds implements Writeable, ToXContent {

    private static final String FEED_ID_FIELD = "feed_id";

    private static final String IOC_ID_FIELD = "ioc_id";

    private static final String INDEX_FIELD = "index";

    private final String feedId;

    private final String iocId;

    private final String index;

    public IocWithFeeds(String iocId, String feedId, String index) {
        this.iocId = iocId;
        this.feedId = feedId;
        this.index = index;
    }

    public IocWithFeeds(StreamInput sin) throws IOException {
        this.iocId = sin.readString();
        this.feedId = sin.readString();
        this.index = sin.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(iocId);
        out.writeString(feedId);
        out.writeString(index);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(IOC_ID_FIELD, iocId)
                .field(FEED_ID_FIELD, feedId)
                .field(INDEX_FIELD, index)
                .endObject();
        return builder;
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                FEED_ID_FIELD, feedId,
                IOC_ID_FIELD, iocId,
                INDEX_FIELD, index
        );
    }

    public String getIocId() {
        return iocId;
    }

    public String getFeedId() {
        return feedId;
    }

    public String getIndex() {
        return index;
    }

    public static IocWithFeeds parse(XContentParser xcp) throws IOException {
        String iocId = null;
        String feedId = null;
        String index = null;

        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IOC_ID_FIELD:
                    iocId = xcp.text();
                    break;
                case FEED_ID_FIELD:
                    feedId = xcp.text();
                    break;
                case INDEX_FIELD:
                    index = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new IocWithFeeds(iocId, feedId, index);
    }

    public static IocWithFeeds readFrom(StreamInput sin) throws IOException {
        return new IocWithFeeds(sin);
    }

    @Override
    public int hashCode() {
        return Objects.hash(feedId, index, iocId);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IocWithFeeds that = (IocWithFeeds) o;

        if (feedId != null ? !feedId.equals(that.feedId) : that.feedId != null) return false;
        if (iocId != null ? !iocId.equals(that.iocId) : that.iocId != null) return false;
        return index != null ? index.equals(that.index) : that.index == null;
    }

    @Override
    public String toString() {
        return "IocWithFeeds{" +
                "feedId='" + feedId + '\'' +
                ", iocId='" + iocId + '\'' +
                ", index='" + index + '\'' +
                '}';
    }
}