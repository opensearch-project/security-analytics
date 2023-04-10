/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;


import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class GetFindingsResponse extends ActionResponse implements ToXContentObject {

    private static final String TOTAL_FINDINGS_FIELD = "total_findings";
    private static final String FINDINGS_FIELD = "findings";

    private Integer totalFindings;
    private List<FindingDto> findings;

    public GetFindingsResponse(Integer totalFindings, List<FindingDto> findings) {
        super();
        this.totalFindings = totalFindings;
        this.findings = findings;
    }

    public GetFindingsResponse(StreamInput sin) throws IOException {
        this.totalFindings = sin.readOptionalInt();
        Collections.unmodifiableList(sin.readList(FindingDto::new));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalInt(totalFindings);
        out.writeCollection(findings);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(TOTAL_FINDINGS_FIELD, totalFindings)
                .field(FINDINGS_FIELD, findings);
        return builder.endObject();
    }

    public Integer getTotalFindings() {
        return totalFindings;
    }

    public List<FindingDto> getFindings() {
        return findings;
    }
}