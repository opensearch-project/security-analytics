/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.clustermanager.ClusterManagerNodeRequest;
import org.opensearch.common.ParseField;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ObjectParser;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;

import java.io.IOException;

import static org.opensearch.action.ValidateActions.addValidationError;

public class GetIndexMappingsRequest extends ClusterManagerNodeRequest<GetIndexMappingsRequest> {

    private static final ObjectParser<GetIndexMappingsRequest, Void> PARSER
            = new ObjectParser(
                    SecurityAnalyticsPlugin.PLUGIN_NAME_URI + SecurityAnalyticsPlugin.MAPPER_BASE_URI + "/get");
    static {
        PARSER.declareString(GetIndexMappingsRequest::setIndexName, new ParseField("indexName"));
    }

    String indexName;

    public GetIndexMappingsRequest() {}

    public GetIndexMappingsRequest(String indexName) {
        this.indexName = indexName;
    }

    public GetIndexMappingsRequest(StreamInput in) throws IOException {
        super(in);
        indexName = in.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError("indexName is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(indexName);
    }

    public static GetIndexMappingsRequest parse(XContentParser parser) throws IOException {
        return PARSER.parse(parser, new GetIndexMappingsRequest(), null);
    }

    public GetIndexMappingsRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }
}
