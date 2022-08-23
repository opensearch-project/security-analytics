/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.alerting.model.Monitor;
import org.opensearch.securityanalytics.model2.ModelSerializer;

import java.io.IOException;

public class ExecuteMonitorResponse extends ActionResponse implements ToXContentObject {

    private static final Logger LOG = LogManager.getLogger(ExecuteMonitorResponse.class);

    private final Monitor monitor;

    public ExecuteMonitorResponse(final Monitor monitor) {
        this.monitor = monitor;
    }

    public ExecuteMonitorResponse(final StreamInput input) throws IOException {
        this.monitor = ModelSerializer.read(input, Monitor.class);
    }

    @Override
    public void writeTo(final StreamOutput output) throws IOException {
        ModelSerializer.write(output, this.monitor);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, ToXContent.Params params) throws IOException {
        return ModelSerializer.write(xContentBuilder, this.monitor);
        // return xContentBuilder.startObject().field(Tokens.MONITOR_ID, this.monitorId).endObject();
    }

    @Override
    public boolean isFragment() {
        return false;
    }
}