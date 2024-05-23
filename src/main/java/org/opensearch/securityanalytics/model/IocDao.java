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

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.IOC_DOMAIN_INDEX_NAME;
import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.IOC_HASH_INDEX_NAME;
import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.IOC_IP_INDEX_NAME;

public class IocDao implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(IocDao.class);

    public static final String NO_ID = "";

    static final String ID_FIELD = "id";
    static final String NAME_FIELD = "name";
    static final String TYPE_FIELD = "type";
    static final String VALUE_FIELD = "value";
    static final String SEVERITY_FIELD = "severity";
    static final String SPEC_VERSION_FIELD = "spec_version";
    static final String CREATED_FIELD = "created";
    static final String MODIFIED_FIELD = "modified";
    static final String DESCRIPTION_FIELD = "description";
    static final String LABELS_FIELD = "labels";
    static final String FEED_ID_FIELD = "feed_id";

    private String id;
    private String name;
    private IocType type;
    private String value;
    private String severity;
    private String specVersion;
    private Instant created;
    private Instant modified;
    private String description;
    private List<String> labels;
    private String feedId;

    public IocDao(
            String id,
            String name,
            IocType type,
            String value,
            String severity,
            String specVersion,
            Instant created,
            Instant modified,
            String description,
            List<String> labels,
            String feedId
    ) {
        this.id = id == null ? NO_ID : id;
        this.name = name;
        this.type = type;
        this.value = value;
        this.severity = severity;
        this.specVersion = specVersion;
        this.created = created;
        this.modified = modified;
        this.description = description;
        this.labels = labels == null ? Collections.emptyList() : labels;
        this.feedId = feedId;
        validate();
    }

    public IocDao(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readString(), // name
                sin.readEnum(IocType.class), // type
                sin.readString(), // value
                sin.readString(), // severity
                sin.readString(), // specVersion
                sin.readInstant(), // created
                sin.readInstant(), // modified
                sin.readString(), // description
                sin.readStringList(), // labels
                sin.readString() // feedId
        );
    }

    public IocDao(IocDto iocDto) {
        this(
                iocDto.getId(),
                iocDto.getName(),
                iocDto.getType(),
                iocDto.getValue(),
                iocDto.getSeverity(),
                iocDto.getSpecVersion(),
                iocDto.getCreated(),
                iocDto.getModified(),
                iocDto.getDescription(),
                iocDto.getLabels(),
                iocDto.getFeedId()
        );
    }

    public static IocDao readFrom(StreamInput sin) throws IOException {
        return new IocDao(sin);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeEnum(type);
        out.writeString(value);
        out.writeString(severity);
        out.writeString(specVersion);
        out.writeInstant(created);
        out.writeInstant(modified);
        out.writeString(description);
        out.writeStringCollection(labels);
        out.writeString(feedId);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(ID_FIELD, id)
                .field(NAME_FIELD, name)
                .field(TYPE_FIELD, type)
                .field(VALUE_FIELD, value)
                .field(SEVERITY_FIELD, severity)
                .field(SPEC_VERSION_FIELD, specVersion)
                .timeField(CREATED_FIELD, created)
                .timeField(MODIFIED_FIELD, modified)
                .field(DESCRIPTION_FIELD, description)
                .field(LABELS_FIELD, labels)
                .field(FEED_ID_FIELD, feedId)
                .endObject();
    }

    public static IocDao parse(XContentParser xcp, String id) throws IOException {
        if (id == null) {
            id = NO_ID;
        }

        String name = null;
        IocType type = null;
        String value = null;
        String severity = null;
        String specVersion = null;
        Instant created = null;
        Instant modified = null;
        String description = null;
        List<String> labels = Collections.emptyList();
        String feedId = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case TYPE_FIELD:
                    type = IocType.valueOf(xcp.text().toUpperCase(Locale.ROOT));
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

        return new IocDao(
                id,
                name,
                type,
                value,
                severity,
                specVersion,
                created,
                modified,
                description,
                labels,
                feedId
        );
    }

    /**
     * Validates required fields.
     * @throws IllegalArgumentException
     */
    public void validate() throws IllegalArgumentException {
        if (type == null) {
            throw new IllegalArgumentException(String.format("[%s] is required.", TYPE_FIELD));
        } else if (!Arrays.asList(IocType.values()).contains(type)) {
            logger.debug("Unsupported IocType: {}", type);
            throw new IllegalArgumentException(String.format("[%s] is not supported.", TYPE_FIELD));
        }

        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(String.format("[%s] is required.", VALUE_FIELD));
        }

        if (feedId == null || feedId.isEmpty()) {
            throw new IllegalArgumentException(String.format("[%s] is required.", FEED_ID_FIELD));
        }
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public IocType getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public String getSeverity() {
        return severity;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public Instant getCreated() {
        return created;
    }

    public Instant getModified() {
        return modified;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getLabels() {
        return labels;
    }

    public String getFeedId() {
        return feedId;
    }

    public enum IocType {
        DOMAIN("domain") {
            @Override
            public String getSystemIndexName() {
                return IOC_DOMAIN_INDEX_NAME;
            }
        },
        HASH("hash") { // TODO placeholder
            @Override
            public String getSystemIndexName() {
                return IOC_HASH_INDEX_NAME;
            }
        },
        IP("ip") {
            @Override
            public String getSystemIndexName() {
                return IOC_IP_INDEX_NAME;
            }
        };

        IocType(String type) {}

        public abstract String getSystemIndexName();
    }
}
