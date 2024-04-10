/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

public class CorrelationQuery implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(CorrelationQuery.class);
    private static final String INDEX = "index";
    private static final String QUERY = "query";
    private static final String CATEGORY = "category";

    private static final String FIELD = "field";

    private String index;

    private String query;

    private String category;

    private String field;

    public CorrelationQuery(String index, String query, String category, String field) {
        this.index = index;
        this.query = query;
        this.category = category;
        this.field = field;
    }

    public CorrelationQuery(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readOptionalString(), sin.readString(), sin.readOptionalString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(index);
        out.writeOptionalString(query);
        out.writeString(category);
        out.writeOptionalString(field);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(INDEX, index).field(CATEGORY, category);
        if (query != null) {
            builder.field(QUERY, query);
        }
        if (field != null) {
            builder.field(FIELD, field);
        }
        return builder.endObject();
    }

    public static CorrelationQuery parse(XContentParser xcp) throws IOException {
        String index = null;
        String query = null;
        String category = null;
        String field = null;

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
                case FIELD:
                    field = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CorrelationQuery(index, query, category, field);
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

    public String getField() {
        return field;
    }
}