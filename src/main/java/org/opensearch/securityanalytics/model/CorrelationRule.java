/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

public class CorrelationRule implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(CorrelationRule.class);

    public static final String CORRELATION_RULE_INDEX = ".opensearch-sap-correlation-rules-config";

    private static final String NAME = "name";
    public static final String NO_ID = "";
    public static final Long NO_VERSION = 1L;
    private static final String CORRELATION_QUERIES = "correlate";
    private static final String CORRELATION_TIME_WINDOW = "time_window";
    private static final String TRIGGER_FIELD = "trigger";

    private String id;

    private Long version;

    private String name;

    private List<CorrelationQuery> correlationQueries;

    private Long corrTimeWindow;

    private CorrelationRuleTrigger trigger;

    public CorrelationRule(String id, Long version, String name, List<CorrelationQuery> correlationQueries, Long corrTimeWindow, CorrelationRuleTrigger trigger) {
        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : NO_VERSION;
        this.name = name;
        this.correlationQueries = correlationQueries;
        this.corrTimeWindow = corrTimeWindow != null? corrTimeWindow: 300000L;
        this.trigger = trigger;
    }

    public CorrelationRule(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readLong(), sin.readString(), sin.readList(CorrelationQuery::readFrom), sin.readLong(), sin.readBoolean() ? new CorrelationRuleTrigger(sin) : null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        builder.field(NAME, name);

        CorrelationQuery[] correlationQueries = new CorrelationQuery[] {};
        correlationQueries = this.correlationQueries.toArray(correlationQueries);
        builder.field(CORRELATION_QUERIES, correlationQueries);
        builder.field(CORRELATION_TIME_WINDOW, corrTimeWindow);
        builder.field(TRIGGER_FIELD, trigger);
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(name);

        for (CorrelationQuery query : correlationQueries) {
            query.writeTo(out);
        }

        out.writeBoolean(trigger != null);
        if (trigger != null) {
            trigger.writeTo(out);
        }
        out.writeLong(corrTimeWindow);
    }

    public static CorrelationRule parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String name = null;
        List<CorrelationQuery> correlationQueries = new ArrayList<>();
        Long corrTimeWindow = null;
        CorrelationRuleTrigger trigger = null;
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME:
                    name = xcp.text();
                    break;
                case CORRELATION_QUERIES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        CorrelationQuery query = CorrelationQuery.parse(xcp);
                        correlationQueries.add(query);
                    }
                    break;
                case CORRELATION_TIME_WINDOW:
                    corrTimeWindow = xcp.longValue();
                    break;
                case TRIGGER_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        trigger = null;
                    } else {
                        trigger = CorrelationRuleTrigger.parse(xcp);
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CorrelationRule(id, version, name, correlationQueries, corrTimeWindow, trigger);
    }

    public static CorrelationRule readFrom(StreamInput sin) throws IOException {
        return new CorrelationRule(sin);
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public Long getVersion() {
        return version;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public List<CorrelationQuery> getCorrelationQueries() {
        return correlationQueries;
    }

    public Long getCorrTimeWindow() {
        return corrTimeWindow;
    }

    public CorrelationRuleTrigger getCorrelationTrigger() {
        return trigger;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CorrelationRule that = (CorrelationRule) o;
        return id.equals(that.id)
                && version.equals(that.version)
                && name.equals(that.name)
                && correlationQueries.equals(that.correlationQueries)
                && trigger.equals(that.trigger);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, version, name, correlationQueries);
    }
}