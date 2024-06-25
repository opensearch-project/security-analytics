/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

/**
 * A data transfer object for STIX2IOC containing additional details.
 */
public class DetailedSTIX2IOCDto implements Writeable, ToXContentObject {
    public static final String NUM_FINDINGS_FIELD = "num_findings";
    STIX2IOCDto ioc;
    private long numFindings = 0L;

    public DetailedSTIX2IOCDto(
            STIX2IOCDto ioc,
            long numFindings
    ) {
        this.ioc = ioc;
        this.numFindings = numFindings;
    }

    public DetailedSTIX2IOCDto(StreamInput sin) throws IOException {
        this(STIX2IOCDto.readFrom(sin), sin.readLong());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        ioc.writeTo(out);
        out.writeLong(numFindings);
    }

    public static DetailedSTIX2IOCDto parse(XContentParser xcp, String id, Long version) throws IOException {
        STIX2IOCDto ioc = STIX2IOCDto.parse(xcp, id, version);
        long numFindings = 0;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NUM_FINDINGS_FIELD:
                    numFindings = xcp.longValue();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new DetailedSTIX2IOCDto(ioc, numFindings);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(STIX2IOC.ID_FIELD, ioc.getId())
                .field(STIX2IOC.NAME_FIELD, ioc.getName())
                .field(STIX2IOC.TYPE_FIELD, ioc.getType())
                .field(STIX2IOC.VALUE_FIELD, ioc.getValue())
                .field(STIX2IOC.SEVERITY_FIELD, ioc.getSeverity())
                .timeField(STIX2IOC.CREATED_FIELD, ioc.getCreated())
                .timeField(STIX2IOC.MODIFIED_FIELD, ioc.getModified())
                .field(STIX2IOC.DESCRIPTION_FIELD, ioc.getDescription())
                .field(STIX2IOC.LABELS_FIELD, ioc.getLabels())
                .field(STIX2IOC.FEED_ID_FIELD, ioc.getFeedId())
                .field(STIX2IOC.SPEC_VERSION_FIELD, ioc.getSpecVersion())
                .field(STIX2IOC.VERSION_FIELD, ioc.getVersion())
                .field(NUM_FINDINGS_FIELD, numFindings)
                .endObject();
    }

    public STIX2IOCDto getIoc() {
        return ioc;
    }

    public void setIoc(STIX2IOCDto ioc) {
        this.ioc = ioc;
    }

    public long getNumFindings() {
        return numFindings;
    }

    public void setNumFindings(Long numFindings) {
        this.numFindings = numFindings;
    }
}
