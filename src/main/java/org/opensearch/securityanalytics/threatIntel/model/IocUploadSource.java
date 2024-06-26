package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.model.STIX2IOCDto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class IocUploadSource extends Source implements Writeable, ToXContent {
    public static final String IOCS_FIELD = "iocs";
    private List<STIX2IOCDto> iocs;

    public IocUploadSource(List<STIX2IOCDto> iocs) {
        this.iocs = iocs;
    }

    public IocUploadSource(StreamInput sin) throws IOException {
        this (
                Collections.unmodifiableList(sin.readList(STIX2IOCDto::new))
        );
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(iocs);
    }

    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(IOC_UPLOAD_FIELD);
        builder.startObject()
                .field(IOCS_FIELD, iocs);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    @Override
    String name() {
        return IOC_UPLOAD_FIELD;
    }

    public static IocUploadSource parse(XContentParser xcp) throws IOException {
        List<STIX2IOCDto> iocs = null;

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case IOCS_FIELD:
                    iocs = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        iocs.add(STIX2IOCDto.parse(xcp, null, null));
                    }
                    break;
                default:
                    break;
            }
        }
        return new IocUploadSource(iocs);
    }

}
