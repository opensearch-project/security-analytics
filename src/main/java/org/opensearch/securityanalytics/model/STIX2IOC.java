/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.lucene.uid.Versions;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class STIX2IOC extends STIX2 implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(STIX2IOC.class);

    public static final String NO_ID = "";
    public static final long NO_VERSION = Versions.NOT_FOUND;

    public static final String VERSION_FIELD = "version";

    private long version = NO_VERSION;

    public STIX2IOC() {
        super();
    }

    public STIX2IOC(STIX2 ioc) {
        super(
                ioc.getId(),
                ioc.getName(),
                ioc.getType(),
                ioc.getValue(),
                ioc.getSeverity(),
                ioc.getCreated(),
                ioc.getModified(),
                ioc.getDescription(),
                ioc.getLabels(),
                ioc.getFeedId(),
                ioc.getSpecVersion()
        );
    }
    
    public STIX2IOC(
            String id,
            String name,
            IOCType type,
            String value,
            String severity,
            Instant created,
            Instant modified,
            String description,
            List<String> labels,
            String feedId,
            String specVersion,
            Long version
    ) {
        super(id, name, type, value, severity, created, modified, description, labels, feedId, specVersion);
        this.version = version;
        validate();
    }

    public STIX2IOC(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readString(), // name
                sin.readEnum(IOCType.class), // type
                sin.readString(), // value
                sin.readString(), // severity
                sin.readInstant(), // created
                sin.readInstant(), // modified
                sin.readString(), // description
                sin.readStringList(), // labels
                sin.readString(), // feedId
                sin.readString(), // specVersion
                sin.readLong() // version
        );
    }

    public STIX2IOC(STIX2IOCDto iocDto) {
        this(
                iocDto.getId(),
                iocDto.getName(),
                iocDto.getType(),
                iocDto.getValue(),
                iocDto.getSeverity(),
                iocDto.getCreated(),
                iocDto.getModified(),
                iocDto.getDescription(),
                iocDto.getLabels(),
                iocDto.getFeedId(),
                iocDto.getSpecVersion(),
                iocDto.getVersion()
        );
    }

    public static STIX2IOC readFrom(StreamInput sin) throws IOException {
        return new STIX2IOC(sin);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(super.getId());
        out.writeString(super.getName());
        out.writeEnum(super.getType());
        out.writeString(super.getValue());
        out.writeString(super.getSeverity());
        out.writeInstant(super.getCreated());
        out.writeInstant(super.getModified());
        out.writeString(super.getDescription());
        out.writeStringCollection(super.getLabels());
        out.writeString(super.getFeedId());
        out.writeString(super.getSpecVersion());
        out.writeLong(version);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(ID_FIELD, super.getId())
                .field(NAME_FIELD, super.getName())
                .field(TYPE_FIELD, super.getType())
                .field(VALUE_FIELD, super.getValue())
                .field(SEVERITY_FIELD, super.getSeverity())
                .timeField(CREATED_FIELD, super.getCreated())
                .timeField(MODIFIED_FIELD, super.getModified())
                .field(DESCRIPTION_FIELD, super.getDescription())
                .field(LABELS_FIELD, super.getLabels())
                .field(FEED_ID_FIELD, super.getFeedId())
                .field(SPEC_VERSION_FIELD, super.getSpecVersion())
                .field(VERSION_FIELD, version)
                .endObject();
    }

    public static STIX2IOC parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }

        if (version == null) {
            version = NO_VERSION;
        }

        String name = null;
        IOCType type = null;
        String value = null;
        String severity = null;
        Instant created = null;
        Instant modified = null;
        String description = null;
        List<String> labels = Collections.emptyList();
        String feedId = null;
        String specVersion = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case TYPE_FIELD:
                    type = IOCType.valueOf(xcp.text().toUpperCase(Locale.ROOT));
                    break;
                case VALUE_FIELD:
                    value = xcp.text();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case SPEC_VERSION_FIELD:
                    specVersion = xcp.text();
                    break;
                case CREATED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        created = null;
                    } else if (xcp.currentToken().isValue()) {
                        created = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        created = null;
                    }
                    break;
                case MODIFIED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        modified = null;
                    } else if (xcp.currentToken().isValue()) {
                        modified = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        modified = null;
                    }
                    break;
                case DESCRIPTION_FIELD:
                    description = xcp.text();
                    break;
                case LABELS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String entry = xcp.textOrNull();
                        if (entry != null) {
                            labels.add(entry);
                        }
                    }
                    break;
                case FEED_ID_FIELD:
                    feedId = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new STIX2IOC(
                id,
                name,
                type,
                value,
                severity,
                created,
                modified,
                description,
                labels,
                feedId,
                specVersion,
                version
        );
    }

    /**
     * Validates required fields.
     * @throws IllegalArgumentException when invalid.
     */
    public void validate() throws IllegalArgumentException {
        if (super.getType() == null) {
            throw new IllegalArgumentException(String.format("[%s] is required.", TYPE_FIELD));
        } else if (!Arrays.asList(IOCType.values()).contains(super.getType())) {
            logger.debug("Unsupported IOCType: {}", super.getType());
            throw new IllegalArgumentException(String.format("[%s] is not supported.", TYPE_FIELD));
        }

        if (super.getValue() == null || super.getValue().isEmpty()) {
            throw new IllegalArgumentException(String.format("[%s] is required.", VALUE_FIELD));
        }

        if (super.getFeedId() == null || super.getFeedId().isEmpty()) {
            throw new IllegalArgumentException(String.format("[%s] is required.", FEED_ID_FIELD));
        }
    }

    public Long getVersion() {
        return version;
    }
}
