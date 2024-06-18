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
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class SAGetTIFSourceConfigResponse extends ActionResponse implements ToXContentObject {
    private final String id;

    private final Long version;

    private final RestStatus status;

    private final SATIFSourceConfigDto SaTifSourceConfigDto;


    public SAGetTIFSourceConfigResponse(String id, Long version, RestStatus status, SATIFSourceConfigDto SaTifSourceConfigDto) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.SaTifSourceConfigDto = SaTifSourceConfigDto;
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
        if (SaTifSourceConfigDto != null) {
            out.writeBoolean((true));
            SaTifSourceConfigDto.writeTo(out);
        } else {
            out.writeBoolean(false);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version);
        builder.startObject("tif_config")
                .field(SATIFSourceConfigDto.NAME_FIELD, SaTifSourceConfigDto.getName())
                .field(SATIFSourceConfigDto.FORMAT_FIELD, SaTifSourceConfigDto.getFormat())
                .field(SATIFSourceConfigDto.TYPE_FIELD, SaTifSourceConfigDto.getType())
                .field(SATIFSourceConfigDto.DESCRIPTION_FIELD, SaTifSourceConfigDto.getDescription())
                .field(SATIFSourceConfigDto.STATE_FIELD, SaTifSourceConfigDto.getState())
                .field(SATIFSourceConfigDto.ENABLED_TIME_FIELD, SaTifSourceConfigDto.getEnabledTime())
                .field(SATIFSourceConfigDto.ENABLED_FIELD, SaTifSourceConfigDto.isEnabled())
                .field(SATIFSourceConfigDto.CREATED_AT_FIELD, SaTifSourceConfigDto.getCreatedAt())
                .field(SATIFSourceConfigDto.LAST_UPDATE_TIME_FIELD, SaTifSourceConfigDto.getLastUpdateTime())
                .field(SATIFSourceConfigDto.LAST_REFRESHED_TIME_FIELD, SaTifSourceConfigDto.getLastRefreshedTime())
                .field(SATIFSourceConfigDto.REFRESH_TYPE_FIELD, SaTifSourceConfigDto.getRefreshType())
                .field(SATIFSourceConfigDto.LAST_REFRESHED_USER_FIELD, SaTifSourceConfigDto.getLastRefreshedUser())
                .field(SATIFSourceConfigDto.SCHEDULE_FIELD, SaTifSourceConfigDto.getSchedule())
                .field(SATIFSourceConfigDto.SOURCE_FIELD, SaTifSourceConfigDto.getSource())
                .field(SATIFSourceConfigDto.CREATED_BY_USER_FIELD, SaTifSourceConfigDto.getCreatedByUser())
                .field(SATIFSourceConfigDto.IOC_TYPES_FIELD, SaTifSourceConfigDto.getIocTypes())
                .endObject();
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
        return SaTifSourceConfigDto;
    }
}