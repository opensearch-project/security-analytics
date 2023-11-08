/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;

public class ThreatIntelIndicesResponse extends ActionResponse {

    private Boolean isAcknowledged;

    private List<String> indices;

    public ThreatIntelIndicesResponse(Boolean isAcknowledged, List<String> indices) {
        super();
        this.isAcknowledged = isAcknowledged;
        this.indices = indices;
    }

    public ThreatIntelIndicesResponse(StreamInput sin) throws IOException {
        this(sin.readBoolean(), sin.readStringList());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(isAcknowledged);
        out.writeStringCollection(indices);
    }

    public Boolean isAcknowledged() {
        return isAcknowledged;
    }

    public List<String> getIndices() {
        return indices;
    }
}