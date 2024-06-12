package org.opensearch.securityanalytics.threatIntel.model.monitor;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ThreatIntelTrigger implements Writeable, ToXContentObject {
    public static final String DATA_SOURCES = "data_sources";
    public static final String IOC_TYPES = "ioc_types";
    List<String> dataSources;
    List<String> iocTypes;

    public ThreatIntelTrigger(List<String> dataSources, List<String> iocTypes) {
        this.dataSources = dataSources == null ? Collections.emptyList() : dataSources;
        this.iocTypes = iocTypes == null ? Collections.emptyList() : iocTypes;
    }

    public ThreatIntelTrigger(StreamInput sin) throws IOException {
        this(
                sin.readStringList(),
                sin.readStringList()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(dataSources);
        out.writeStringCollection(iocTypes);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(DATA_SOURCES, dataSources)
                .field(IOC_TYPES, iocTypes)
                .endObject();
    }

    public static ThreatIntelTrigger readFrom(StreamInput sin) throws IOException {
        return new ThreatIntelTrigger(sin);
    }

    public static ThreatIntelTrigger parse(XContentParser xcp) throws IOException {
        List<String> iocTypes = new ArrayList<>();
        List<String> dataSources = new ArrayList<>();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IOC_TYPES:
                    List<String> vals = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        vals.add(xcp.text());
                    }
                    iocTypes.addAll(vals);
                    break;
                case DATA_SOURCES:
                    List<String> ds = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        ds.add(xcp.text());
                    }
                    dataSources.addAll(ds);
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new ThreatIntelTrigger(dataSources, iocTypes);
    }

    public List<String> getDataSources() {
        return dataSources;
    }

    public List<String> getIocTypes() {
        return iocTypes;
    }
}
