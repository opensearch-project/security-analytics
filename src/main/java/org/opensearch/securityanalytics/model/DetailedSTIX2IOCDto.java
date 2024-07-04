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
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.model.STIX2;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
        long numFindings = 0;
        if (id == null) {
            id = STIX2IOC.NO_ID;
        }

        if (version == null) {
            version = STIX2IOC.NO_VERSION;
        }

        String name = null;
        IOCType type = null;
        String value = null;
        String severity = null;
        Instant created = null;
        Instant modified = null;
        String description = null;
        List<String> labels = new ArrayList<>();
        String specVersion = null;
        String feedId = null;
        String feedName = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case STIX2.ID_FIELD:
                    if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                        id = xcp.text();
                    }
                    break;
                case STIX2IOC.VERSION_FIELD:
                    if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                        version = xcp.longValue();
                    }
                    break;
                case STIX2.NAME_FIELD:
                    name = xcp.text();
                    break;
                case STIX2.TYPE_FIELD:
                    type = new IOCType(xcp.text().toLowerCase(Locale.ROOT));
                    break;
                case STIX2.VALUE_FIELD:
                    value = xcp.text();
                    break;
                case STIX2.SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case STIX2.CREATED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        created = null;
                    } else if (xcp.currentToken().isValue()) {
                        if (xcp.currentToken() == XContentParser.Token.VALUE_STRING) {
                            created = Instant.parse(xcp.text());
                        } else if (xcp.currentToken() == XContentParser.Token.VALUE_NUMBER) {
                            created = Instant.ofEpochMilli(xcp.longValue());
                        }
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        created = null;
                    }
                    break;
                case STIX2.MODIFIED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        modified = null;
                    } else if (xcp.currentToken().isValue()) {
                        if (xcp.currentToken() == XContentParser.Token.VALUE_STRING) {
                            modified = Instant.parse(xcp.text());
                        } else if (xcp.currentToken() == XContentParser.Token.VALUE_NUMBER) {
                            modified = Instant.ofEpochMilli(xcp.longValue());
                        }
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        modified = null;
                    }
                    break;
                case STIX2.DESCRIPTION_FIELD:
                    description = xcp.text();
                    break;
                case STIX2.LABELS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String entry = xcp.textOrNull();
                        if (entry != null) {
                            labels.add(entry);
                        }
                    }
                    break;
                case STIX2.SPEC_VERSION_FIELD:
                    specVersion = xcp.text();
                    break;
                case STIX2IOC.FEED_ID_FIELD:
                    feedId = xcp.text();
                    break;
                case STIX2IOC.FEED_NAME_FIELD:
                    feedName = xcp.text();
                    break;
                case NUM_FINDINGS_FIELD:
                    numFindings = xcp.longValue();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new DetailedSTIX2IOCDto(new STIX2IOCDto(
                id,
                name,
                type,
                value,
                severity,
                created,
                modified,
                description,
                labels,
                specVersion,
                feedId,
                feedName,
                version
        ), numFindings);
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
                .field(STIX2IOC.FEED_NAME_FIELD, ioc.getFeedName())
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
