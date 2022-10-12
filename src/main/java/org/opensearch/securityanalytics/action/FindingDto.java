package org.opensearch.securityanalytics.action;

import java.io.IOException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.commons.alerting.model.FindingWithDocs;

public class FindingDto implements ToXContentObject, Writeable {

    String detectorId;

    FindingWithDocs finding;

    public FindingDto(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                new FindingWithDocs(sin)
        );
    }

    public FindingDto(String detectorId, FindingWithDocs finding) {
        this.detectorId = detectorId;
        this.finding = finding;
    }

    public static AlertDto readFrom(StreamInput sin) throws IOException {
        return new AlertDto(sin);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
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
