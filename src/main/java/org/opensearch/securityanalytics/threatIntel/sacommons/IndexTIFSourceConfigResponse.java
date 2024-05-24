///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//package org.opensearch.securityanalytics.threatIntel.action;
//
//import org.opensearch.core.action.ActionResponse;
//import org.opensearch.core.common.io.stream.StreamInput;
//import org.opensearch.core.common.io.stream.StreamOutput;
//import org.opensearch.core.xcontent.ToXContentObject;
//import org.opensearch.core.xcontent.XContentBuilder;
//import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
//import org.opensearch.securityanalytics.threatIntel.model.SATIFConfig;
//
//import java.io.IOException;
//import java.time.Instant;
//import java.util.List;
//
//import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
//import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;
//
//public class IndexTIFConfigResponse extends ActionResponse implements ToXContentObject {
//    private String id;
//    private Long version;
//    private String feedFormat;
//    private String feedName;
//    private TIFJobState state;
//    private Integer numFindings;
//    private Integer numIOCs;
//    private Instant lastActivatedTime;
//    private Instant lastRefreshedTime;
//    private String refreshInterval;
//
////    private Source source;
//    private String createdByUser;
//    private String feedType;
//    private Boolean licenseRequired;
//    private Integer numScansConfigured;
//    private List<String> iocTypes;
//
//    public IndexTIFConfigResponse(String feedId, Long version, String feedFormat, String feedName, TIFJobState state, Integer numFindings,
//                                  Integer numIOCs, Instant lastActivatedTime, Instant lastRefreshedTime, String refreshInterval, String createdByUser,
//                                  String feedType, Boolean licenseRequired, Integer numScansConfigured, List<String> iocTypes) {
//        super();
//        this.id = feedId;
//        this.version = version;
//        this.feedFormat = feedFormat;
//        this.feedName = feedName;
//        this.state = state;
//        this.numFindings = numFindings;
//        this.numIOCs = numIOCs;
//        this.lastActivatedTime = lastActivatedTime;
//        this.lastRefreshedTime = lastRefreshedTime;
//        this.refreshInterval = refreshInterval;
//        this.createdByUser = createdByUser;
//        this.feedType = feedType;
//        this.licenseRequired = licenseRequired;
//        this.numScansConfigured = numScansConfigured;
//        this.iocTypes = iocTypes;
//    }
//
//    public IndexTIFConfigResponse(StreamInput sin) throws IOException {
//        this.id = sin.readString();
//        this.version = sin.readLong();
//        this.feedFormat = sin.readString();
//        this.feedName = sin.readString();
//        this.state = TIFJobState.valueOf(sin.readString());
//        this.numFindings = sin.readInt();
//        this.numIOCs = sin.readInt();
//        this.lastActivatedTime = sin.readInstant();
//        this.lastRefreshedTime = sin.readInstant();
//        this.refreshInterval = sin.readString();
//        this.createdByUser = sin.readString();
//        this.feedType = sin.readString();
//        this.licenseRequired = sin.readBoolean();
//        this.numScansConfigured = sin.readInt();
//        this.iocTypes = sin.readStringList();
//    }
//
//    @Override
//    public void writeTo(StreamOutput out) throws IOException {
//        out.writeString(id);
//        out.writeString(feedFormat);
//        out.writeString(feedName);
//        out.writeString(state.name());
//        out.writeInt(numFindings);
//        out.writeInt(numIOCs);
//        out.writeInstant(lastActivatedTime);
//        out.writeInstant(lastRefreshedTime);
//        out.writeString(refreshInterval);
//        out.writeString(createdByUser);
//        out.writeString(feedType);
//        out.writeBoolean(licenseRequired);
//        out.writeInt(numScansConfigured);
//        out.writeStringCollection(iocTypes);
//    }
//
//    @Override
//    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
//        builder.startObject()
//                .field(_ID, id)
//                .field(_VERSION, version);
//
//        builder.startObject("tif_config")
//                .field(SATIFConfig.FEED_FORMAT_FIELD, feedFormat)
//                .field(SATIFConfig.FEED_NAME_FIELD, feedName)
//                .field(SATIFConfig.STATE_FIELD, state)
//                .field("num_findings", numFindings)
//                .field("num_iocs", numIOCs)
//                .field(SATIFConfig.ENABLED_TIME_FIELD, lastActivatedTime)
//                .field(SATIFConfig.RefreshStats.LAST_REFRESHED_TIME_FIELD, lastRefreshedTime)
//                .field("refresh_interval", refreshInterval)
//                .field(SATIFConfig.CREATED_BY_USER_FIELD, createdByUser)
//                .field(SATIFConfig.FEED_FORMAT_FIELD, feedType)
//                .field("license_required", licenseRequired)
//                .field("num_scans_configured", numScansConfigured)
//                .field("ioc_types", iocTypes)
//                .endObject();
//        return builder.endObject();
//    }
//
//}

/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.sacommons;

public interface IndexTIFSourceConfigResponse {
    String getTIFConfigId();
    Long getVersion();
    TIFSourceConfigDto getTIFConfigDto();
}