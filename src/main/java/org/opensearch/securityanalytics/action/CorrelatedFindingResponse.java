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
import org.opensearch.securityanalytics.model.FindingWithScore;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class CorrelatedFindingResponse extends ActionResponse implements ToXContentObject {

    private List<FindingWithScore> findings;

    protected static final String FINDINGS = "findings";

    public CorrelatedFindingResponse(List<FindingWithScore> findings) {
        super();
        this.findings = findings;
    }

    public CorrelatedFindingResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(FindingWithScore::new))
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(findings);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(FINDINGS, findings)
                .endObject();
        return builder;
    }
}