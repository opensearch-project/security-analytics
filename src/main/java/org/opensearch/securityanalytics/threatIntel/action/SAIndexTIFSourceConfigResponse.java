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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfigDto;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class SAIndexTIFSourceConfigResponse extends ActionResponse implements ToXContentObject, IndexTIFSourceConfigResponse {
    private final String tifConfigId;
    private final Long version;
    private final RestStatus status;
    private final SATIFSourceConfigDto saTIFConfigDto;

    public SAIndexTIFSourceConfigResponse(String id, Long version, RestStatus status, SATIFSourceConfigDto tifConfig) {
        super();
        this.tifConfigId = id;
        this.version = version;
        this.status = status;
        this.saTIFConfigDto = tifConfig;
    }

    public SAIndexTIFSourceConfigResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(), // tif config id
                sin.readLong(), // version
                sin.readEnum(RestStatus.class), // status
                SATIFSourceConfigDto.readFrom(sin) // SA tif config dto
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(tifConfigId);
        out.writeLong(version);
        out.writeEnum(status);
        saTIFConfigDto.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(_ID, tifConfigId)
                .field(_VERSION, version);

        builder.startObject("tif_config")
                .field(SATIFSourceConfigDto.FEED_FORMAT_FIELD, saTIFConfigDto.getFeedFormat())
                .field(SATIFSourceConfigDto.FEED_NAME_FIELD, saTIFConfigDto.getName())
                .field(SATIFSourceConfigDto.FEED_TYPE_FIELD, saTIFConfigDto.getFeedType())
                .field(SATIFSourceConfigDto.STATE_FIELD, saTIFConfigDto.getState())
                .field(SATIFSourceConfigDto.ENABLED_TIME_FIELD, saTIFConfigDto.getEnabledTime())
                .field(SATIFSourceConfigDto.ENABLED_FIELD, saTIFConfigDto.isEnabled())
                .field(SATIFSourceConfigDto.LAST_REFRESHED_TIME_FIELD, saTIFConfigDto.getLastRefreshedTime())
                .field(SATIFSourceConfigDto.SCHEDULE_FIELD, saTIFConfigDto.getSchedule())
                // source
                .field(SATIFSourceConfigDto.CREATED_BY_USER_FIELD, saTIFConfigDto.getCreatedByUser())
                .field(SATIFSourceConfigDto.IOC_TYPES_FIELD, saTIFConfigDto.getIocTypes())
                .endObject();

        return builder.endObject();
    }
    @Override
    public String getTIFConfigId() {
        return tifConfigId;
    }
    @Override
    public Long getVersion() {
        return version;
    }
    @Override
    public TIFSourceConfigDto getTIFConfigDto() {
        return saTIFConfigDto;
    }
    public RestStatus getStatus() {
        return status;
    }

}