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
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import static org.opensearch.securityanalytics.model.Detector.NO_ID;

public class IocDao implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(IocDao.class);

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
    private List<String> value;
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
            List<String> value,
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
        this.feedId = feedId == null ? NO_ID : feedId;
    }

    public IocDao(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readString(), // name
                sin.readEnum(IocType.class), // type
                sin.readStringList(), // value
                sin.readString(), // severity
                sin.readString(), // specVersion
                sin.readInstant(), // created
                sin.readInstant(), // modified
                sin.readString(), // description
                sin.readStringList(), // labels
                sin.readString() // feedId
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeEnum(type);
        out.writeStringCollection(value);
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
        List<String> value = Collections.emptyList();
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
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String entry = xcp.textOrNull();
                        if (entry != null) {
                            value.add(entry);
                        }
                    }
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

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public IocType getType() {
        return type;
    }

    public List<String> getValue() {
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
        DOMAIN("domain-name"),
        HASH("hash"), // TODO placeholder
        IP("ipv4-addr"); // TODO placeholder as we don't want to limit to ipv4

        IocType(String type) {}
    }
}
