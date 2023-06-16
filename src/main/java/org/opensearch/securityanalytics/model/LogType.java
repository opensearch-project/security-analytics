/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class LogType implements Writeable, ToXContentObject {

    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String DESCRIPTION = "description";
    private static final String IS_BUILTIN = "is_builtin";
    private static final String MAPPINGS = "mappings";
    private static final String RAW_FIELD = "raw_field";
    private static final String ECS = "ecs";
    private static final String OCSF = "ocsf";

    private String id;
    private String name;
    private String description;
    private Boolean isBuiltIn;
    private List<Mapping> mappings;

    public LogType(String id, String name, String description, boolean isBuiltIn, List<Mapping> mappings) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.isBuiltIn = isBuiltIn;
        this.mappings = mappings;
    }

    public LogType(Map<String, Object> logTypeAsMap) {
        this.id = (String) logTypeAsMap.get(ID);
        this.name = (String) logTypeAsMap.get(NAME);
        this.description = (String) logTypeAsMap.get(DESCRIPTION);
        if (logTypeAsMap.containsKey(IS_BUILTIN)) {
            this.isBuiltIn = (Boolean) logTypeAsMap.get(IS_BUILTIN);
        }
        List<Map<String, String>> mappings = (List<Map<String, String>>)logTypeAsMap.get(MAPPINGS);
        if (mappings.size() > 0) {
            this.mappings = new ArrayList<>(mappings.size());
            this.mappings = mappings.stream().map(e ->
                    new Mapping(e.get(RAW_FIELD), e.get(ECS), e.get(OCSF))
            ).collect(Collectors.toList());
        }
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public boolean getIsBuiltIn() { return isBuiltIn; }

    public List<Mapping> getMappings() {
        return mappings;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeString(description);

        for(Mapping m : mappings) {
            out.writeString(m.getRawField());
            out.writeString(m.getEcs());
            out.writeString(m.getOcsf());
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME, name);
        builder.field(DESCRIPTION, description);

        builder.startArray(MAPPINGS);
        for(Mapping m : mappings) {
            builder.startObject();
            builder.field(RAW_FIELD, m.getRawField());
            builder.field(ECS, m.getEcs());
            builder.field(OCSF, m.getOcsf());
            builder.endObject();
        }
        builder.endArray();
        return builder.endObject();
    }

    @Override
    public String toString() {
        return name;
    }

    public static class Mapping {
        private String rawField;
        private String ecs;
        private String ocsf;

        public Mapping(String rawField, String ecs, String ocsf) {
            this.rawField = rawField;
            this.ecs = ecs;
            this.ocsf = ocsf;
        }

        public String getRawField() {
            return rawField;
        }

        public String getEcs() {
            return ecs;
        }

        public String getOcsf() {
            return ocsf;
        }
    }

}
