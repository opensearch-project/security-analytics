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
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;


import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class GetFindingsResponse extends ActionResponse implements ToXContentObject {


    Integer totalFindings;
    List<FindingDto> findings;
    String detectorId;

    public GetFindingsResponse(Integer totalFindings, List<FindingDto> findings, String detectorId) {
        super();
        this.totalFindings = totalFindings;
        this.findings = findings;
        this.detectorId = detectorId;
    }

    public GetFindingsResponse(StreamInput sin) throws IOException {
        this.totalFindings = sin.readOptionalInt();
        Collections.unmodifiableList(sin.readList(FindingDto::new));
        this.detectorId = sin.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalInt(totalFindings);
        out.writeCollection(findings);
        out.writeString(detectorId);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("detectorId", detectorId)
                .field("total_findings", totalFindings)
                .field("findings", findings);
        return builder.endObject();
    }

    public Integer getTotalFindings() {
        return totalFindings;
    }

    public List<FindingDto> getFindings() {
        return findings;
    }

    public String getDetectorId() {
        return detectorId;
    }
}