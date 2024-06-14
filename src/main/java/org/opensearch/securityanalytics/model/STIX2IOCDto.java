/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

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

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * A data transfer object for the [STIX2IOC] data model.
 */
public class STIX2IOCDto implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(STIX2IOCDto.class);

    private String id;
    private String name;
    private IOCType type;
    private String value;
    private String severity;
    private Instant created;
    private Instant modified;
    private String description;
    private List<String> labels;
    private String feedId;
    private String specVersion;
    private long version;

    // No arguments contructor needed for parsing from S3
    public STIX2IOCDto() {}

    public STIX2IOCDto(
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
            long version
    ) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.value = value;
        this.severity = severity;
        this.created = created;
        this.modified = modified;
        this.description = description;
        this.labels = labels;
        this.feedId = feedId;
        this.specVersion = specVersion;
        this.version = version;
    }

    public STIX2IOCDto(STIX2IOC ioc) {
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
                ioc.getFeedId(),
                ioc.getSpecVersion(),
                ioc.getVersion()
        );
    }

    public STIX2IOCDto(StreamInput sin) throws IOException {
        this(new STIX2IOC(sin));
    }

    public static STIX2IOCDto readFrom(StreamInput sin) throws IOException {
        return new STIX2IOCDto(sin);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeEnum(type);
        out.writeString(value);
        out.writeString(severity);
        out.writeInstant(created);
        out.writeInstant(modified);
        out.writeString(description);
        out.writeStringCollection(labels);
        out.writeString(feedId);
        out.writeString(specVersion);
        out.writeLong(version);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(STIX2IOC.ID_FIELD, id)
                .field(STIX2IOC.NAME_FIELD, name)
                .field(STIX2IOC.TYPE_FIELD, type)
                .field(STIX2IOC.VALUE_FIELD, value)
                .field(STIX2IOC.SEVERITY_FIELD, severity)
                .timeField(STIX2IOC.CREATED_FIELD, created)
                .timeField(STIX2IOC.MODIFIED_FIELD, modified)
                .field(STIX2IOC.DESCRIPTION_FIELD, description)
                .field(STIX2IOC.LABELS_FIELD, labels)
                .field(STIX2IOC.FEED_ID_FIELD, feedId)
                .field(STIX2IOC.SPEC_VERSION_FIELD, specVersion)
                .field(STIX2IOC.VERSION_FIELD, version)
                .endObject();
    }

    public static STIX2IOCDto parse(XContentParser xcp, String id, Long version) throws IOException {
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
        List<String> labels = Collections.emptyList();
        String feedId = null;
        String specVersion = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case STIX2.NAME_FIELD:
                    name = xcp.text();
                    break;
                case STIX2.TYPE_FIELD:
                    type = IOCType.valueOf(xcp.text().toUpperCase(Locale.ROOT));
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
                        created = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        created = null;
                    }
                    break;
                case STIX2.MODIFIED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        modified = null;
                    } else if (xcp.currentToken().isValue()) {
                        modified = Instant.ofEpochMilli(xcp.longValue());
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
                case STIX2.FEED_ID_FIELD:
                    feedId = xcp.text();
                    break;
                case STIX2.SPEC_VERSION_FIELD:
                    specVersion = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new STIX2IOCDto(
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

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public IOCType getType() {
        return type;
    }

    public void setType(IOCType type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Instant getCreated() {
        return created;
    }

    public void setCreated(Instant created) {
        this.created = created;
    }

    public Instant getModified() {
        return modified;
    }

    public void setModified(Instant modified) {
        this.modified = modified;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getLabels() {
        return labels;
    }

    public void setLabels(List<String> labels) {
        this.labels = labels;
    }

    public String getFeedId() {
        return feedId;
    }

    public void setFeedId(String feedId) {
        this.feedId = feedId;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }
}
