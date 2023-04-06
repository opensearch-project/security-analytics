package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import static org.opensearch.action.ValidateActions.addValidationError;

public class ExternalSourceRuleImportRequest extends ActionRequest {

    public static final String SOURCE_ID = "source_id";

    String sourceId;

    public ExternalSourceRuleImportRequest(String sourceId) {
        super();
        this.sourceId = sourceId;
    }

    public ExternalSourceRuleImportRequest(StreamInput sin) throws IOException {
        this(sin.readString());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (sourceId == null || sourceId.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", SOURCE_ID), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(sourceId);
    }

    public static ExternalSourceRuleImportRequest parse(XContentParser xcp) throws IOException {
        String sourceId = null;

        if (xcp.currentToken() == null) {
            xcp.nextToken();
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case SOURCE_ID:
                    sourceId = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new ExternalSourceRuleImportRequest(sourceId);
    }

    public ExternalSourceRuleImportRequest indexName(String sourceId) {
        this.sourceId = sourceId;
        return this;
    }

    public String getSourceId() {
        return this.sourceId;
    }

    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
    }
}
