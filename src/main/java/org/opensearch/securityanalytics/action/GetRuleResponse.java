/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class GetRuleResponse extends ActionResponse implements ToXContentObject {

    private String id;
    private Long version;
    private RestStatus status;
    private Rule rule;

    public GetRuleResponse(String id, Long version, RestStatus status, Rule rule) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.rule = rule;
    }

    public GetRuleResponse(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readLong(),
             sin.readEnum(RestStatus.class),
             sin.readBoolean()? Rule.readFrom(sin): null);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        if (rule != null) {
            out.writeBoolean(true);
            rule.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version);
        builder.startObject("rule")
                .field(Rule.TITLE, rule.getTitle())
                .field(Rule.CATEGORY, rule.getCategory())
                .field(Rule.LOG_SOURCE, rule.getLogSource())
                .field(Rule.DESCRIPTION, rule.getDescription())
                .field(Rule.TAGS, rule.getTags())
                .field(Rule.REFERENCES, rule.getReferences())
                .field(Rule.LEVEL, rule.getLevel())
                .field(Rule.FALSE_POSITIVES, rule.getFalsePositives())
                .field(Rule.AUTHOR, rule.getAuthor())
                .field(Rule.STATUS, rule.getStatus())
                .field(Rule.LAST_UPDATE_TIME_FIELD, rule.getDate())
                .field(Rule.QUERIES, rule.getQueries())
                .field(Rule.RULE, rule.getRule())
                .endObject();
        return builder.endObject();
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public RestStatus getStatus() {
        return status;
    }

    public Rule getRule() {
        return rule;
    }
}
