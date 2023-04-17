package org.opensearch.securityanalytics.model;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

public class CorrelationQuery implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(CorrelationQuery.class);
    private static final String INDEX = "index";
    private static final String QUERY = "query";
    private static final String CATEGORY = "category";

    private String index;

    private String query;

    private String category;

    public CorrelationQuery(String index, String query, String category) {
        this.index = index;
        this.query = query;
        this.category = category;
    }

    public CorrelationQuery(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(index);
        out.writeString(query);
        out.writeString(category);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(INDEX, index).field(QUERY, query).field(CATEGORY, category);
        return builder.endObject();
    }

    public static CorrelationQuery parse(XContentParser xcp) throws IOException {
        String index = null;
        String query = null;
        String category = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case INDEX:
                    index = xcp.text();
                    break;
                case QUERY:
                    query = xcp.text();
                    break;
                case CATEGORY:
                    category = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CorrelationQuery(index, query, category);
    }

    public static CorrelationQuery readFrom(StreamInput sin) throws IOException {
        return new CorrelationQuery(sin);
    }

    public String getIndex() {
        return index;
    }

    public String getQuery() {
        return query;
    }

    public String getCategory() {
        return category;
    }
}