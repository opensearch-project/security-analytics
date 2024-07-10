/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.util.XContentUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

public class STIX2IOC extends STIX2 implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(STIX2IOC.class);

    public static final String NO_ID = "";
    public static final long NO_VERSION = 1L;

    public static final String VERSION_FIELD = "version";

    private long version = NO_VERSION;

    public STIX2IOC() {
        super();
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
            String specVersion,
            String feedId,
            String feedName,
            Long version
    ) {
        super(StringUtils.isBlank(id) ? UUID.randomUUID().toString() : id, name, type, value, severity, created, modified, description, labels, specVersion, feedId, feedName);
        this.version = version;
        validate();
    }

    // Constructor used when downloading IOCs from S3
    public STIX2IOC(STIX2 ioc, String feedId, String feedName) {
        this(
                ioc.getId(),
                ioc.getName(),
                ioc.getType(),
                ioc.getValue(),
                ioc.getSeverity(),
                ioc.getCreated(),
                ioc.getModified(),
                ioc.getDescription(),
                ioc.getLabels(),
                ioc.getSpecVersion(),
                feedId,
                feedName,
                NO_VERSION
        );
    }

    public STIX2IOC(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readString(), // name
                new IOCType(sin.readString()), // type
                sin.readString(), // value
                sin.readString(), // severity
                sin.readInstant(), // created
                sin.readInstant(), // modified
                sin.readString(), // description
                sin.readStringList(), // labels
                sin.readString(), // specVersion
                sin.readString(), // feedId
                sin.readString(), // feedName
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
                iocDto.getSpecVersion(),
                iocDto.getFeedId(),
                iocDto.getFeedName(),
                iocDto.getVersion()
        );
    }

    public STIX2IOC(STIX2IOCDto ioc, String feedId, String feedName) {
        this(
                ioc.getId(),
                ioc.getName(),
                ioc.getType(),
                ioc.getValue(),
                ioc.getSeverity(),
                ioc.getCreated(),
                ioc.getModified(),
                ioc.getDescription(),
                ioc.getLabels(),
                ioc.getSpecVersion(),
                feedId,
                feedName,
                NO_VERSION
        );
    }

    public static STIX2IOC readFrom(StreamInput sin) throws IOException {
        return new STIX2IOC(sin);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(super.getId());
        out.writeString(super.getName());
        out.writeString(super.getType().getType());
        out.writeString(super.getValue());
        out.writeString(super.getSeverity());
        out.writeInstant(super.getCreated());
        out.writeInstant(super.getModified());
        out.writeString(super.getDescription());
        out.writeStringCollection(super.getLabels());
        out.writeString(super.getSpecVersion());
        out.writeString(super.getFeedId());
        out.writeString(super.getFeedName());
        out.writeLong(version);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(ID_FIELD, super.getId())
                .field(NAME_FIELD, super.getName())
                .field(TYPE_FIELD, super.getType().getType())
                .field(VALUE_FIELD, super.getValue())
                .field(SEVERITY_FIELD, super.getSeverity());
        XContentUtils.buildInstantAsField(builder, super.getCreated(), CREATED_FIELD);
        XContentUtils.buildInstantAsField(builder, super.getModified(), MODIFIED_FIELD);
        return builder.field(DESCRIPTION_FIELD, super.getDescription())
                .field(LABELS_FIELD, super.getLabels())
                .field(SPEC_VERSION_FIELD, super.getSpecVersion())
                .field(FEED_ID_FIELD, super.getFeedId())
                .field(FEED_NAME_FIELD, super.getFeedName())
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
        List<String> labels = new ArrayList<>();
        String specVersion = null;
        String feedId = null;
        String feedName = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case TYPE_FIELD:
                    type = new IOCType(xcp.text());
                    break;
                case VALUE_FIELD:
                    value = xcp.text();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case CREATED_FIELD:
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
                case MODIFIED_FIELD:
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
                case SPEC_VERSION_FIELD:
                    specVersion = xcp.text();
                    break;
                case FEED_ID_FIELD:
                    feedId = xcp.text();
                    break;
                case FEED_NAME_FIELD:
                    feedName = xcp.text();
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
                specVersion,
                feedId,
                feedName,
                version
        );
    }

    /**
     * Validates required fields.
     *
     * @throws IllegalArgumentException when invalid.
     */
    public void validate() throws IllegalArgumentException {
        if (super.getType() == null) {
            throw new IllegalArgumentException(String.format("[%s] is required.", TYPE_FIELD));
        } else if (!IOCType.supportedType(super.getType().getType())) {
            logger.debug("Unsupported IOCType: {}", super.getType().getType());
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
