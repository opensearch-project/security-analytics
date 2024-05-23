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

public class IocDto implements Writeable, ToXContentObject {
    private static final Logger logger = LogManager.getLogger(IocDto.class);

    private String id;
    private String name;
    private IocDao.IocType type;
    private String value;
    private String severity;
    private String specVersion;
    private Instant created;
    private Instant modified;
    private String description;
    private List<String> labels;
    private String feedId;

    public IocDto(IocDao iocDao) {
        this.id = iocDao.getId();
        this.name = iocDao.getName();
        this.type = iocDao.getType();
        this.value = iocDao.getValue();
        this.severity = iocDao.getSeverity();
        this.specVersion = iocDao.getSpecVersion();
        this.created = iocDao.getCreated();
        this.modified = iocDao.getModified();
        this.description = iocDao.getDescription();
        this.labels = iocDao.getLabels();
        this.feedId = iocDao.getFeedId();
    }

    public IocDto(StreamInput sin) throws IOException {
        this(new IocDao(sin));
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
                .field(IocDao.ID_FIELD, id)
                .field(IocDao.NAME_FIELD, name)
                .field(IocDao.TYPE_FIELD, type)
                .field(IocDao.VALUE_FIELD, value)
                .field(IocDao.SEVERITY_FIELD, severity)
                .field(IocDao.SPEC_VERSION_FIELD, specVersion)
                .timeField(IocDao.CREATED_FIELD, created)
                .timeField(IocDao.MODIFIED_FIELD, modified)
                .field(IocDao.DESCRIPTION_FIELD, description)
                .field(IocDao.LABELS_FIELD, labels)
                .field(IocDao.FEED_ID_FIELD, feedId)
                .endObject();
    }

    public static IocDto parse(XContentParser xcp, String id) throws IOException {
            return new IocDto(IocDao.parse(xcp, id));
        }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public IocDao.IocType getType() {
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
