package org.opensearch.securityanalytics.threatIntel.action.monitor.response;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.IndexIocScanMonitorResponseInterface;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;

/**
 * Response object resturned for request that indexes ioc scan monitor
 */
public class IndexThreatIntelMonitorResponse extends ActionResponse implements ToXContentObject, IndexIocScanMonitorResponseInterface {
    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String SEQ_NO = "seq_no";
    private static final String PRIMARY_TERM = "primary_term";
    private static final String MONITOR = "monitor";

    private final String id;
    private final long version;
    private final long seqNo;
    private final long primaryTerm;
    private final ThreatIntelMonitorDto iocScanMonitor;

    public IndexThreatIntelMonitorResponse(String id, long version, long seqNo, long primaryTerm, ThreatIntelMonitorDto monitor) {
        this.id = id;
        this.version = version;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.iocScanMonitor = monitor;
    }

    public IndexThreatIntelMonitorResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(), // version
                sin.readLong(), // seqNo
                sin.readLong(), // primaryTerm
                ThreatIntelMonitorDto.readFrom(sin) // monitor
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeLong(seqNo);
        out.writeLong(primaryTerm);
        iocScanMonitor.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject()
                .field(ID, id)
                .field(NAME, version)
                .field(SEQ_NO, seqNo)
                .field(PRIMARY_TERM, primaryTerm)
                .field(MONITOR, iocScanMonitor)
                .endObject();
    }

    @Override
    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public long getSeqNo() {
        return seqNo;
    }

    public long getPrimaryTerm() {
        return primaryTerm;
    }

    @Override
    public ThreatIntelMonitorDto getIocScanMonitor() {
        return iocScanMonitor;
    }
}