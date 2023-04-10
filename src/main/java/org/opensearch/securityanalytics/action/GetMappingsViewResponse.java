/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.opensearch.Version;
import org.opensearch.action.ActionResponse;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.mapper.MapperUtils;

public class GetMappingsViewResponse extends ActionResponse implements ToXContentObject {

    public static final String UNMAPPED_INDEX_FIELDS = "unmapped_index_fields";
    public static final String UNMAPPED_FIELD_ALIASES = "unmapped_field_aliases";

    private Map<String, Object> aliasMappings;
    List<String> unmappedIndexFields;
    List<String> unmappedFieldAliases;

    public GetMappingsViewResponse(
            Map<String, Object> aliasMappings,
            List<String> unmappedIndexFields,
            List<String> unmappedFieldAliases
            ) {
        this.aliasMappings = aliasMappings;
        this.unmappedIndexFields = unmappedIndexFields;
        this.unmappedFieldAliases = unmappedFieldAliases;
    }

    public GetMappingsViewResponse(StreamInput in) throws IOException {
        super(in);
        if (in.readBoolean()) {
            aliasMappings = in.readMap();
        }
        int unmappedIndexFieldsSize = in.readVInt();
        if (unmappedIndexFieldsSize > 0) {
            unmappedIndexFields = new ArrayList<>(unmappedIndexFieldsSize);
            for (int i = 0; i < unmappedIndexFieldsSize; i++) {
                unmappedIndexFields.add(in.readString());
            }
        }
        int unmappedFieldAliasesSize = in.readVInt();
        if (unmappedFieldAliasesSize > 0) {
            unmappedFieldAliases = new ArrayList<>(unmappedFieldAliasesSize);
            for (int i = 0; i < unmappedFieldAliasesSize; i++) {
                unmappedFieldAliases.add(in.readString());
            }
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (aliasMappings != null) {
            out.writeBoolean(true);
            out.writeMap(aliasMappings);
        } else {
            out.writeBoolean(false);
        }
        if (unmappedIndexFields != null) {
            out.writeVInt(unmappedIndexFields.size());
            for (String f : unmappedIndexFields) {
                out.writeString(f);
            }
        } else {
            out.writeVInt(0);
        }
        if (unmappedFieldAliases != null) {
            out.writeVInt(unmappedFieldAliases.size());
            for (String f : unmappedFieldAliases) {
                out.writeString(f);
            }
        } else {
            out.writeVInt(0);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (aliasMappings != null && aliasMappings.size() > 0) {
            builder.field(MapperUtils.PROPERTIES, (Map<String, ?>) aliasMappings.get(MapperUtils.PROPERTIES));
        }
        if (unmappedIndexFields != null && unmappedIndexFields.size() > 0) {
            builder.field(UNMAPPED_INDEX_FIELDS, unmappedIndexFields);
        }
        if (unmappedFieldAliases != null && unmappedFieldAliases.size() > 0) {
            builder.field(UNMAPPED_FIELD_ALIASES, unmappedFieldAliases);
        }
        return builder.endObject();
    }

    public Map<String, Object> aliasMappings() {
        return aliasMappings;
    }

    public List<String> unmappedFieldAliases() {
        return unmappedFieldAliases;
    }

    public List<String> unmappedIndexFields() {
        return unmappedIndexFields;
    }

    public Map<String, Object> getAliasMappings() {
        return aliasMappings;
    }

    public List<String> getUnmappedFieldAliases() {
        return unmappedFieldAliases;
    }

    public List<String> getUnmappedIndexFields() {
        return unmappedIndexFields;
    }

    @Override
    public String toString() {
        return Strings.toString(XContentType.JSON, this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(new Object[]{this.aliasMappings, this.unmappedFieldAliases, this.unmappedIndexFields});
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        GetMappingsViewResponse other = (GetMappingsViewResponse) obj;
        return this.aliasMappings.equals(other.aliasMappings) &&
               this.unmappedIndexFields.equals(other.unmappedIndexFields) &&
               this.unmappedFieldAliases.equals(other.unmappedFieldAliases);
    }
}
