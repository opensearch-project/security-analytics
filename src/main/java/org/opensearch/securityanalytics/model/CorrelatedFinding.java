/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CorrelatedFinding implements Writeable, ToXContentObject {

    private String finding1;

    private String logType1;

    private String finding2;

    private String logType2;

    private List<String> correlationRules;

    protected static final String FINDING1_FIELD = "finding1";
    protected static final String LOGTYPE1_FIELD = "logType1";
    protected static final String FINDING2_FIELD = "finding2";
    protected static final String LOGTYPE2_FIELD = "logType2";
    protected static final String RULES_FIELD = "rules";

    public CorrelatedFinding(String finding1, String logType1, String finding2, String logType2, List<String> correlationRules) {
        this.finding1 = finding1;
        this.logType1 = logType1;
        this.finding2 = finding2;
        this.logType2 = logType2;
        this.correlationRules = correlationRules;
    }

    public CorrelatedFinding(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readStringList()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(finding1);
        out.writeString(logType1);
        out.writeString(finding2);
        out.writeString(logType2);
        out.writeStringCollection(correlationRules);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(FINDING1_FIELD, finding1)
                .field(LOGTYPE1_FIELD, logType1)
                .field(FINDING2_FIELD, finding2)
                .field(LOGTYPE2_FIELD, logType2)
                .field(RULES_FIELD, correlationRules);
        return builder.endObject();
    }

    public static CorrelatedFinding parse(XContentParser xcp) throws IOException {
        String finding1 = null;
        String logType1 = null;
        String finding2 = null;
        String logType2 = null;
        List<String> correlationRules = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case FINDING1_FIELD:
                    finding1 = xcp.text();
                    break;
                case LOGTYPE1_FIELD:
                    logType1 = xcp.text();
                    break;
                case FINDING2_FIELD:
                    finding2 = xcp.text();
                    break;
                case LOGTYPE2_FIELD:
                    logType2 = xcp.text();
                    break;
                case RULES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        correlationRules.add(xcp.text());
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CorrelatedFinding(finding1, logType1, finding2, logType2, correlationRules);
    }

    public static CorrelatedFinding readFrom(StreamInput sin) throws IOException {
        return new CorrelatedFinding(sin);
    }
}