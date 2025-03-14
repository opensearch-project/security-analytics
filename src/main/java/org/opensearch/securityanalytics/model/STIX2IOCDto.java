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
import org.opensearch.securityanalytics.commons.model.STIX2;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A data transfer object for the [STIX2IOC] data model.
 */
public class STIX2IOCDto implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(STIX2IOCDto.class);

    private String id;
    private String name;
    private String type;
    private String value;
    private String severity;
    private Instant created;
    private Instant modified;
    private String description;
    private List<String> labels;
    private String specVersion;
    private String feedId;
    private String feedName;
    private long version;

    // No arguments constructor needed for parsing from S3
    public STIX2IOCDto() {}

    public STIX2IOCDto(
            String id,
            String name,
            String type,
            String value,
            String severity,
            Instant created,
            Instant modified,
            String description,
            List<String> labels,
            String specVersion,
            String feedId,
            String feedName,
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
        this.specVersion = specVersion;
        this.feedId = feedId;
        this.feedName = feedName;
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
                ioc.getSpecVersion(),
                ioc.getFeedId(),
                ioc.getFeedName(),
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
        out.writeString(type.toString());
        out.writeString(value);
        out.writeString(severity);
        out.writeInstant(created);
        out.writeInstant(modified);
        out.writeString(description);
        out.writeStringCollection(labels);
        out.writeString(specVersion);
        out.writeString(feedId);
        out.writeString(feedName);
        out.writeLong(version);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(STIX2IOC.ID_FIELD, id)
                .field(STIX2IOC.NAME_FIELD, name)
                .field(STIX2IOC.TYPE_FIELD, type.toString())
                .field(STIX2IOC.VALUE_FIELD, value)
                .field(STIX2IOC.SEVERITY_FIELD, severity)
                .timeField(STIX2IOC.CREATED_FIELD, created)
                .timeField(STIX2IOC.MODIFIED_FIELD, modified)
                .field(STIX2IOC.DESCRIPTION_FIELD, description)
                .field(STIX2IOC.LABELS_FIELD, labels)
                .field(STIX2IOC.SPEC_VERSION_FIELD, specVersion)
                .field(STIX2IOC.FEED_ID_FIELD, feedId)
                .field(STIX2IOC.FEED_NAME_FIELD, feedName)
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
        String type = null;
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
                    id = getString(xcp, id);
                    break;
                case STIX2IOC.VERSION_FIELD:
                    if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                        version = xcp.longValue();
                    }
                    break;
                case STIX2.NAME_FIELD:
                    name = getString(xcp, name);
                    break;
                case STIX2.TYPE_FIELD:
                    type = getString(xcp, type);
                    break;
                case STIX2.VALUE_FIELD:
                    value = getString(xcp, value);
                    break;
                case STIX2.SEVERITY_FIELD:
                    severity = getString(xcp, severity);
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
                    description = getString(xcp, description);
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
                    specVersion = getString(xcp, specVersion);
                    break;
                case STIX2IOC.FEED_ID_FIELD:
                    feedId = getString(xcp, feedId);
                    break;
                case STIX2IOC.FEED_NAME_FIELD:
                    feedName = getString(xcp, feedName);
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
                specVersion,
                feedId,
                feedName,
                version
        );
    }

    private static String getString(XContentParser xcp, final String currVal) throws IOException {
        if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
            return xcp.text();
        } else {
            return currVal;
        }
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

    public String getType() {
        return type;
    }

    public void setType(String type) {
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

    public String getSpecVersion() {
        return specVersion;
    }

    public String getFeedId() {
        return feedId;
    }

    public String getFeedName() {
        return feedName;
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }
}
