/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class SAGetTIFSourceConfigResponse extends ActionResponse implements ToXContentObject {
    private final String id;

    private final Long version;

    private final RestStatus status;

    private final SATIFSourceConfigDto saTifSourceConfigDto;


    public SAGetTIFSourceConfigResponse(String id, Long version, RestStatus status, SATIFSourceConfigDto saTifSourceConfigDto) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.saTifSourceConfigDto = saTifSourceConfigDto;
    }

    public SAGetTIFSourceConfigResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readLong(), // version
                sin.readEnum(RestStatus.class), // status
                sin.readBoolean()? SATIFSourceConfigDto.readFrom(sin) : null // SA tif config dto
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        if (saTifSourceConfigDto != null) {
            out.writeBoolean((true));
            saTifSourceConfigDto.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version);
        saTifSourceConfigDto.innerXcontent(builder);
        return builder.endObject();
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public RestStatus getStatus() {
        return status;
    }

    public SATIFSourceConfigDto getSaTifSourceConfigDto() {
        return saTifSourceConfigDto;
    }
}