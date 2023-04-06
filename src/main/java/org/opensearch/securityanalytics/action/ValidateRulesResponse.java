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
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.mapper.MapperUtils;

public class ValidateRulesResponse extends ActionResponse implements ToXContentObject {

    public static final String NONAPPLICABLE_FIELDS = "nonapplicable_fields";

    List<String> nonapplicableFields;

    public ValidateRulesResponse(List<String> nonapplicableFields) {
        this.nonapplicableFields = nonapplicableFields;
    }

    public ValidateRulesResponse(StreamInput in) throws IOException {
        super(in);
        nonapplicableFields = in.readStringList();
        int size = in.readVInt();
        if (size > 0) {
            nonapplicableFields = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
                nonapplicableFields.add(in.readString());
            }
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (nonapplicableFields != null) {
            out.writeVInt(nonapplicableFields.size());
            for (String f : nonapplicableFields) {
                out.writeString(f);
            }
        } else {
            out.writeVInt(0);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (nonapplicableFields != null && nonapplicableFields.size() > 0) {
            builder.field(NONAPPLICABLE_FIELDS, nonapplicableFields);
        }
        return builder.endObject();
    }

    public List<String> getNonapplicableFields() {
        return nonapplicableFields;
    }

    @Override
    public String toString() {
        return Strings.toString(XContentType.JSON, this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(new Object[]{this.nonapplicableFields});
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }
        ValidateRulesResponse other = (ValidateRulesResponse) obj;
        return this.nonapplicableFields.equals(other.nonapplicableFields);
    }
}
