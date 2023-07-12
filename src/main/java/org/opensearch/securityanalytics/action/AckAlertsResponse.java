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

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class AckAlertsResponse extends ActionResponse implements ToXContentObject {

    private final List<AlertDto> acknowledged;
    private final List<AlertDto> failed;
    private final List<String> missing;

    public AckAlertsResponse(List<AlertDto> acknowledged, List<AlertDto> failed, List<String> missing) {
        this.acknowledged = acknowledged;
        this.failed = failed;
        this.missing = missing;
    }

    public AckAlertsResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(AlertDto::new)),
                Collections.unmodifiableList(sin.readList(AlertDto::new)),
                Collections.unmodifiableList(sin.readStringList())
        );
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {
        streamOutput.writeList(this.acknowledged);
        streamOutput.writeList(this.failed);
        streamOutput.writeStringCollection(this.missing);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("acknowledged",this.acknowledged)
                .field("failed",this.failed)
                .field("missing",this.missing);
        return builder.endObject();
    }

    public List<AlertDto> getAcknowledged() {
        return acknowledged;
    }

    public List<AlertDto> getFailed() {
        return failed;
    }

    public List<String> getMissing() {
        return missing;
    }
}