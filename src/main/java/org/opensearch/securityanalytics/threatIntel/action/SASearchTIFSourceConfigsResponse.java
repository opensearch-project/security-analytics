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
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SASearchTIFSourceConfigsResponse extends ActionResponse implements ToXContentObject {
    private static final String TIF_SOURCE_CONFIGS_FIELD = "threat_intel_source_configs";
    private final List<SATIFSourceConfigDto> SaTifSourceConfigDtos;


    public SASearchTIFSourceConfigsResponse(List<SATIFSourceConfigDto> SaTifSourceConfigDtos) {
        super();
        this.SaTifSourceConfigDtos = SaTifSourceConfigDtos;
    }

    public SASearchTIFSourceConfigsResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(SATIFSourceConfigDto::new))
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(this.SaTifSourceConfigDtos);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(TIF_SOURCE_CONFIGS_FIELD, SaTifSourceConfigDtos);
        return builder.endObject();
    }

    public List<SATIFSourceConfigDto> getSaTifSourceConfigDtos() {
        return SaTifSourceConfigDtos;
    }

}