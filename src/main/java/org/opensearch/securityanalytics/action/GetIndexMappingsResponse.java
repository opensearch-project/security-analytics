/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.opensearch.Version;
import org.opensearch.action.ActionResponse;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.Strings;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.mapper.MapperService;

import java.io.IOException;

public class GetIndexMappingsResponse extends ActionResponse implements ToXContentObject {

    private static final ParseField MAPPINGS = new ParseField("mappings");

    private final Map<String, MappingMetadata> mappings;

    public GetIndexMappingsResponse(final Map<String, MappingMetadata> mappings) {
        this.mappings = mappings;
    }

    public GetIndexMappingsResponse(StreamInput in) throws IOException {
        super(in);
        int size = in.readVInt();
        final Map<String, MappingMetadata> indexMapBuilder = new HashMap<>();
        for (int i = 0; i < size; i++) {
            String index = in.readString();
            if (in.getVersion().before(Version.V_2_0_0)) {
                int mappingCount = in.readVInt();
                if (mappingCount == 0) {
                    indexMapBuilder.put(index, MappingMetadata.EMPTY_MAPPINGS);
                } else if (mappingCount == 1) {
                    String type = in.readString();
                    if (!MapperService.SINGLE_MAPPING_NAME.equals(type)) {
                        throw new IllegalStateException("Expected " + MapperService.SINGLE_MAPPING_NAME + " but got [" + type + "]");
                    }
                    indexMapBuilder.put(index, new MappingMetadata(in));
                } else {
                    throw new IllegalStateException("Expected 0 or 1 mappings but got: " + mappingCount);
                }
            } else {
                boolean hasMapping = in.readBoolean();
                indexMapBuilder.put(index, hasMapping ? new MappingMetadata(in) : MappingMetadata.EMPTY_MAPPINGS);
            }
        }
        mappings = Collections.unmodifiableMap(indexMapBuilder);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeVInt(mappings.size());
        for (Map.Entry<String, MappingMetadata> indexEntry : mappings.entrySet()) {
            out.writeString(indexEntry.getKey());
            if (out.getVersion().before(Version.V_2_0_0)) {
                out.writeVInt(indexEntry.getValue() == MappingMetadata.EMPTY_MAPPINGS ? 0 : 1);
                if (indexEntry.getValue() != MappingMetadata.EMPTY_MAPPINGS) {
                    out.writeString(MapperService.SINGLE_MAPPING_NAME);
                    indexEntry.getValue().writeTo(out);
                }
            } else {
                out.writeOptionalWriteable(indexEntry.getValue());
            }
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        for (final Map.Entry<String, MappingMetadata> indexEntry : getMappings().entrySet()) {
            builder.startObject(indexEntry.getKey());
            if (indexEntry.getValue() != null) {
                builder.field(MAPPINGS.getPreferredName(), indexEntry.getValue().sourceAsMap());
            } else {
                builder.startObject(MAPPINGS.getPreferredName()).endObject();
            }
            builder.endObject();
        }
        builder.endObject();
        return builder;
    }

    public Map<String, MappingMetadata> mappings() {
        return mappings;
    }

    public Map<String, MappingMetadata> getMappings() {
        return mappings();
    }

    @Override
    public String toString() {
        return Strings.toString(XContentType.JSON, this);
    }

    @Override
    public int hashCode() {
        return mappings.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        GetIndexMappingsResponse other = (GetIndexMappingsResponse) obj;
        return this.mappings.equals(other.mappings);
    }
}
