/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.alerting.model.Monitor;
import org.opensearch.securityanalytics.model2.ModelSerializer;

import java.io.IOException;

public class IndexMonitorRequest extends ActionRequest {
    public final String monitorId;
    public final Long seqNo;
    public final Long primaryTerm;
    public final WriteRequest.RefreshPolicy refreshPolicy;
    public final RestRequest.Method method;
    public final Monitor monitor;

    public IndexMonitorRequest(final String monitorId, final Long seqNo, final Long primaryTerm, final WriteRequest.RefreshPolicy refreshPolicy, final RestRequest.Method method, final Monitor monitor) {
        this.monitorId = monitorId;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.monitor = monitor;
    }

    public IndexMonitorRequest(final StreamInput input) throws IOException {
        this(input.readString(), input.readLong(), input.readLong(), WriteRequest.RefreshPolicy.readFrom(input), input.readEnum(RestRequest.Method.class), ModelSerializer.read(input, Monitor.class));

    }

    public ActionRequestValidationException validate() {
        return null;
    }

    public void writeTo(StreamOutput output) throws IOException {
        output.writeString(this.monitorId);
        output.writeLong(this.seqNo);
        output.writeLong(this.primaryTerm);
        this.refreshPolicy.writeTo(output);
        output.writeEnum(this.method);
        ModelSerializer.write(output, this.monitor);
    }
}
