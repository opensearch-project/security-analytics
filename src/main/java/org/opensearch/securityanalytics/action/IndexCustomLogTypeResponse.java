/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.CustomLogType;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class IndexCustomLogTypeResponse extends ActionResponse implements ToXContentObject {

    public static final String CUSTOM_LOG_TYPES_FIELD = "logType";

    private String id;

    private Long version;

    private RestStatus status;

    private CustomLogType customLogType;

    public IndexCustomLogTypeResponse(
            String id,
            Long version,
            RestStatus status,
            CustomLogType customLogType
    ) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.customLogType = customLogType;
    }

    public IndexCustomLogTypeResponse(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readEnum(RestStatus.class),
                CustomLogType.readFrom(sin)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        customLogType.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(_ID, id)
                .field(_VERSION, version)
                .field(CUSTOM_LOG_TYPES_FIELD, customLogType)
                .endObject();
    }

    public String getId() {
        return id;
    }
}