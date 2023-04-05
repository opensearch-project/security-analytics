/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class IndexRuleResponse extends ActionResponse implements ToXContentObject {

    /**
     * the id of the created/updated rule
     */
    private String id;

    /**
     * the version of the created/updated rule
     */
    private Long version;

    /**
     * REST method for the request PUT/POST
     */
    private RestStatus status;

    /**
     * the Rule object of security-analytics
     */
    private Rule rule;

    public IndexRuleResponse(String id, Long version, RestStatus status, Rule rule) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.rule = rule;
    }

    public IndexRuleResponse(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readLong(),
             sin.readEnum(RestStatus.class),
             Rule.readFrom(sin));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        rule.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field(_ID, id)
            .field(_VERSION, version);

        builder.startObject("rule")
            .field(Rule.CATEGORY, rule.getCategory())
            .field(Rule.TITLE, rule.getTitle())
            .field(Rule.LOG_SOURCE, rule.getLogSource())
            .field(Rule.DESCRIPTION, rule.getDescription())
            .field(Rule.TAGS, rule.getTags())
            .field(Rule.REFERENCES, rule.getReferences())
            .field(Rule.LEVEL, rule.getLevel())
            .field(Rule.FALSE_POSITIVES, rule.getFalsePositives())
            .field(Rule.AUTHOR, rule.getAuthor())
            .field(Rule.STATUS, rule.getStatus())
            .field(Detector.LAST_UPDATE_TIME_FIELD, rule.getDate())
            .field(Rule.RULE, rule.getRule())
            .endObject();

        return builder.endObject();
    }

    public String getId() {
        return id;
    }
}