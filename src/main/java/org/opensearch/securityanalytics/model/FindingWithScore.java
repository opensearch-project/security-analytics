/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class FindingWithScore implements Writeable, ToXContentObject {

    protected static final String FINDING = "finding";
    protected static final String DETECTOR_TYPE = "detector_type";
    protected static final String SCORE = "score";

    private String finding;

    private String detectorType;

    private Double score;

    public FindingWithScore(String finding, String detectorType, Double score) {
        this.finding = finding;
        this.detectorType = detectorType;
        this.score = score;
    }

    public FindingWithScore(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readDouble()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(finding);
        out.writeString(detectorType);
        out.writeDouble(score);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(FINDING, finding)
                .field(DETECTOR_TYPE, detectorType)
                .field(SCORE, score)
                .endObject();
        return builder;
    }

    public static FindingWithScore parse(XContentParser xcp) throws IOException {
        String finding = null;
        String detectorType = null;
        Double score = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case FINDING:
                    finding = xcp.text();
                    break;
                case DETECTOR_TYPE:
                    detectorType = xcp.text();
                    break;
                case SCORE:
                    score = xcp.doubleValue();
                    break;
            }
        }
        return new FindingWithScore(finding, detectorType, score);
    }

    public static FindingWithScore readFrom(StreamInput sin) throws IOException {
        return new FindingWithScore(sin);
    }
}