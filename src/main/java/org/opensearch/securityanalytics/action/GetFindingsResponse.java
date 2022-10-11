/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;

public class GetFindingsResponse extends ActionResponse implements ToXContentObject {

    RestStatus status;
    Integer totalFindings;
    List<FindingsDto> findings;


    public GetFindingsResponse(RestStatus status, Integer totalFindings, List<FindingsDto> findings) {
        super();
        this.status = status;
        this.totalFindings = totalFindings;
        this.findings = findings;
    }

    public GetFindingsResponse(StreamInput sin) throws IOException {
        this.status = sin.readEnum(RestStatus.class);
        this.totalFindings = sin.readOptionalInt();
        Integer currentSize = sin.readInt();
        if (currentSize > 0) {
            this.findings = new ArrayList<>(currentSize);
            for (int i = 0; i < currentSize; i++) {
                this.findings.add(FindingsDto.readFrom(sin));
            }
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeEnum(status);
        out.writeOptionalInt(totalFindings);
        out.writeInt(findings.size());
        for (FindingsDto finding : findings) {
            finding.writeTo(out);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("total_findings", totalFindings)
                .field("findings", findings);
        return builder.endObject();
    }


    public RestStatus getStatus() {
        return status;
    }

    public Integer getTotalFindings() {
        return totalFindings;
    }

    public List<FindingsDto> getFindings() {
        return findings;
    }

}