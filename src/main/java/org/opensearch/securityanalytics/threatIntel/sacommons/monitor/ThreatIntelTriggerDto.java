package org.opensearch.securityanalytics.threatIntel.sacommons.monitor;

import org.apache.commons.lang3.StringUtils;
import org.opensearch.commons.alerting.model.action.Action;
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
import java.util.List;
import java.util.UUID;

public class ThreatIntelTriggerDto implements Writeable, ToXContentObject {

    public static final String DATA_SOURCES_FIELD = "data_sources";
    public static final String IOC_TYPES_FIELD = "ioc_types";
    public static final String ACTIONS_FIELD = "actions";
    public static final String ID_FIELD = "id";
    public static final String NAME_FIELD = "name";
    public static final String SEVERITY_FIELD = "severity";

    private final List<String> dataSources;
    private final List<String> iocTypes;
    private final List<Action> actions;
    private final String name;
    private final String id;
    private final String severity;

    public ThreatIntelTriggerDto(List<String> dataSources, List<String> iocTypes, List<Action> actions, String name, String id, String severity) {
        this.dataSources = dataSources == null ? Collections.emptyList() : dataSources;
        this.iocTypes = iocTypes == null ? Collections.emptyList() : iocTypes;
        this.actions = actions;
        this.name = name;
        this.id = StringUtils.isBlank(id) ? UUID.randomUUID().toString() : id;
        this.severity = severity;
    }

    public ThreatIntelTriggerDto(StreamInput sin) throws IOException {
        this(
                sin.readStringList(),
                sin.readStringList(),
                sin.readList(Action::new),
                sin.readString(),
                sin.readString(),
                sin.readString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(dataSources);
        out.writeStringCollection(iocTypes);
        out.writeList(actions);
        out.writeString(name);
        out.writeString(id);
        out.writeString(severity);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(DATA_SOURCES_FIELD, dataSources)
                .field(IOC_TYPES_FIELD, iocTypes)
                .field(ACTIONS_FIELD, actions)
                .field(ID_FIELD, id)
                .field(NAME_FIELD, name)
                .field(SEVERITY_FIELD, severity)
                .endObject();
    }

    public static ThreatIntelTriggerDto readFrom(StreamInput sin) throws IOException {
        return new ThreatIntelTriggerDto(sin);
    }

    public static ThreatIntelTriggerDto parse(XContentParser xcp) throws IOException {
        List<String> iocTypes = new ArrayList<>();
        List<String> dataSources = new ArrayList<>();
        List<Action> actions = new ArrayList<>();
        String name = null;
        String id = null;
        String severity = null;
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case IOC_TYPES_FIELD:
                    List<String> vals = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        vals.add(xcp.text());
                    }
                    iocTypes.addAll(vals);
                    break;
                case DATA_SOURCES_FIELD:
                    List<String> ds = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        ds.add(xcp.text());
                    }
                    dataSources.addAll(ds);
                    break;
                case ACTIONS_FIELD:
                    // Ensure the current token is START_ARRAY, indicating the beginning of the array
                    XContentParserUtils.ensureExpectedToken(
                            XContentParser.Token.START_ARRAY,  // Expected token type
                            xcp.currentToken(),                // Current token from the parser
                            xcp                                // The parser instance
                    );

                    // Iterate through the array until END_ARRAY token is encountered
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        // Parse each array element into an Action object and add it to the actions list
                        actions.add(Action.parse(xcp));
                    }
                    break;
                case ID_FIELD:
                    id = xcp.text();
                    break;
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new ThreatIntelTriggerDto(dataSources, iocTypes, actions, name, id, severity);
    }

    public List<String> getDataSources() {
        return dataSources;
    }

    public List<String> getIocTypes() {
        return iocTypes;
    }

    public List<Action> getActions() {
        return actions;
    }

    public String getName() {
        return name;
    }

    public String getId() {
        return id;
    }

    public String getSeverity() {
        return severity;
    }
}
