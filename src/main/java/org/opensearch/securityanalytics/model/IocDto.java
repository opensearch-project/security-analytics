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

import java.io.IOException;
import java.time.Instant;
import java.util.List;

public class IocDto implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(IocDto.class);

    private String id;
    private String name;
    private IOC.IocType type;
    private String value;
    private String severity;
    private String specVersion;
    private Instant created;
    private Instant modified;
    private String description;
    private List<String> labels;
    private String feedId;

    public IocDto(IOC ioc) {
        this.id = ioc.getId();
        this.name = ioc.getName();
        this.type = ioc.getType();
        this.value = ioc.getValue();
        this.severity = ioc.getSeverity();
        this.specVersion = ioc.getSpecVersion();
        this.created = ioc.getCreated();
        this.modified = ioc.getModified();
        this.description = ioc.getDescription();
        this.labels = ioc.getLabels();
        this.feedId = ioc.getFeedId();
    }

    public IocDto(StreamInput sin) throws IOException {
        this(new IOC(sin));
    }

    public static IocDto readFrom(StreamInput sin) throws IOException {
        return new IocDto(sin);
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
                .field(IOC.ID_FIELD, id)
                .field(IOC.NAME_FIELD, name)
                .field(IOC.TYPE_FIELD, type)
                .field(IOC.VALUE_FIELD, value)
                .field(IOC.SEVERITY_FIELD, severity)
                .field(IOC.SPEC_VERSION_FIELD, specVersion)
                .timeField(IOC.CREATED_FIELD, created)
                .timeField(IOC.MODIFIED_FIELD, modified)
                .field(IOC.DESCRIPTION_FIELD, description)
                .field(IOC.LABELS_FIELD, labels)
                .field(IOC.FEED_ID_FIELD, feedId)
                .endObject();
    }

    public static IocDto parse(XContentParser xcp, String id) throws IOException {
            return new IocDto(IOC.parse(xcp, id));
        }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public IOC.IocType getType() {
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
}
