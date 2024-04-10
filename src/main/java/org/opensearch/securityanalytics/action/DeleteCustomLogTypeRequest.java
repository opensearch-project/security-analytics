/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class DeleteCustomLogTypeRequest extends ActionRequest {

    private String logTypeId;

    private WriteRequest.RefreshPolicy refreshPolicy;

    public DeleteCustomLogTypeRequest(String logTypeId, WriteRequest.RefreshPolicy refreshPolicy) {
        super();
        this.logTypeId = logTypeId;
        this.refreshPolicy = refreshPolicy;
    }

    public DeleteCustomLogTypeRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
                WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(logTypeId);
        refreshPolicy.writeTo(out);
    }

    public String getLogTypeId() {
        return logTypeId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}