/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class GetIocFindingsResponse extends ActionResponse implements ToXContentObject {

    private static final String TOTAL_IOC_FINDINGS_FIELD = "total_findings";

    private static final String IOC_FINDINGS_FIELD = "ioc_findings";

    private Integer totalFindings;

    private List<IocFinding> iocFindings;

    public GetIocFindingsResponse(Integer totalFindings, List<IocFinding> iocFindings) {
        super();
        this.totalFindings = totalFindings;
        this.iocFindings = iocFindings;
    }

    public GetIocFindingsResponse(StreamInput sin) throws IOException {
        this(
                sin.readInt(),
                Collections.unmodifiableList(sin.readList(IocFinding::new))
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeInt(totalFindings);
        out.writeCollection(iocFindings);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(TOTAL_IOC_FINDINGS_FIELD, totalFindings)
                .field(IOC_FINDINGS_FIELD, iocFindings);
        return builder.endObject();
    }

    public Integer getTotalFindings() {
        return totalFindings;
    }

    public List<IocFinding> getIocFindings() {
        return iocFindings;
    }
}