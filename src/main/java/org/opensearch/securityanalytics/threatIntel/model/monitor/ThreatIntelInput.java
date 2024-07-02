package org.opensearch.securityanalytics.threatIntel.model.monitor;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ThreatIntelInput implements Writeable, ToXContentObject {

    public static final String PER_IOC_TYPE_SCAN_INPUTS_FIELD = "per_ioc_type_scan_input_list";
    private final List<PerIocTypeScanInput> perIocTypeScanInputList;

    public ThreatIntelInput(
            List<PerIocTypeScanInput> perIocTypeScanInputList) {
        this.perIocTypeScanInputList = perIocTypeScanInputList;
    }

    public ThreatIntelInput(StreamInput sin) throws IOException {
        this(
                sin.readList(PerIocTypeScanInput::new)
        );
    }

    public static ThreatIntelInput parse(XContentParser xcp) throws IOException {
        List<PerIocTypeScanInput> perIocTypeScanInputs = new ArrayList<>();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case PER_IOC_TYPE_SCAN_INPUTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        PerIocTypeScanInput input = PerIocTypeScanInput.parse(xcp);
                        perIocTypeScanInputs.add(input);
                    }
                    break;
                default:
                    xcp.skipChildren();
                    break;
            }
        }
        return new ThreatIntelInput(perIocTypeScanInputs);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeList(perIocTypeScanInputList);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(PER_IOC_TYPE_SCAN_INPUTS_FIELD, perIocTypeScanInputList)
                .endObject();
    }

    public static PerIocTypeScanInput readFrom(StreamInput sin) throws IOException {
        return new PerIocTypeScanInput(sin);
    }

    public BytesReference getThreatIntelInputAsBytesReference() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();
        this.writeTo(out);
        BytesReference bytes = out.bytes();
        return bytes;
    }

    public List<PerIocTypeScanInput> getPerIocTypeScanInputList() {
        return perIocTypeScanInputList;
    }
}
