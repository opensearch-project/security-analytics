/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.List;
import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.RuleCategory;

public class GetAllRuleCategoriesResponse extends ActionResponse implements ToXContentObject {

    private static final String RULE_CATEGORIES = "rule_categories";

    private List<RuleCategory> ruleCategories;

    public GetAllRuleCategoriesResponse(List<RuleCategory> ruleCategories) {
        super();
        this.ruleCategories = ruleCategories;
    }

    public GetAllRuleCategoriesResponse(StreamInput sin) throws IOException {
        this(sin.readList(RuleCategory::new));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeList(ruleCategories);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startArray(RULE_CATEGORIES);
        for (RuleCategory c : ruleCategories) {
            c.toXContent(builder, null);
        }
        builder.endArray();
        return builder.endObject();
    }
}