/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.opensearch.action.ActionResponse;
import org.opensearch.common.Strings;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.mapper.MapperUtils;

public class ExternalSourceRuleImportResponse extends ActionResponse implements ToXContentObject {

    public static final String ADDED = "added";
    public static final String UPDATED = "updated";
    public static final String DELETED = "deleted";
    public static final String FAILED = "failed";

    private int added;
    private int updated;
    private int deleted;
    private int failed;

    public ExternalSourceRuleImportResponse(int added, int updated, int deleted, int failed) {
        this.added = added;
        this.updated = updated;
        this.deleted = deleted;
        this.failed = failed;
    }

    public ExternalSourceRuleImportResponse(StreamInput in) throws IOException {
        super(in);
        this.added = in.readInt();
        this.updated = in.readInt();
        this.deleted = in.readInt();
        this.failed = in.readInt();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeInt(added);
        out.writeInt(updated);
        out.writeInt(deleted);
        out.writeInt(failed);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(ADDED, added);
        builder.field(UPDATED, updated);
        builder.field(DELETED, deleted);
        builder.field(FAILED, failed);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return Strings.toString(this);
    }

    public int getAdded() {
        return added;
    }

    public int getUpdated() {
        return updated;
    }

    public int getDeleted() {
        return deleted;
    }

    public int getFailed() {
        return failed;
    }
}
