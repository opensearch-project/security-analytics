package org.opensearch.securityanalytics.action;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.commons.alerting.model.FindingWithDocs;

import java.io.IOException;

public class FindingsDto implements ToXContentObject {

    String detectorId;

    FindingWithDocs finding;

    public FindingsDto(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                new FindingWithDocs(sin)
        );
    }

    public FindingsDto(String detectorId, FindingWithDocs finding) {
        this.detectorId = detectorId;
        this.finding = finding;
    }

    public static FindingsDto readFrom(StreamInput sin) throws IOException {
        return new FindingsDto(sin);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("detectorId", detectorId)
                .field("finding", finding);
        return builder.endObject();
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        finding.writeTo(out);
    }
}
