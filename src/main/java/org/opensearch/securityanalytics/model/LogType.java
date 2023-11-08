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
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class LogType implements Writeable {

    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String DESCRIPTION = "description";
    private static final String IS_BUILTIN = "is_builtin";
    private static final String MAPPINGS = "mappings";
    private static final String RAW_FIELD = "raw_field";
    public static final String ECS = "ecs";
    public static final String OCSF = "ocsf";

    private String id;
    private String name;
    private String description;
    private Boolean isBuiltIn;
    private List<Mapping> mappings;

    public LogType(StreamInput sin) throws IOException {
        this.id = sin.readString();
        this.isBuiltIn = sin.readOptionalBoolean();
        this.name = sin.readString();
        this.description = sin.readString();
        this.mappings = sin.readList(Mapping::readFrom);
    }

    public LogType(String id, String name, String description, boolean isBuiltIn, List<Mapping> mappings) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.isBuiltIn = isBuiltIn;
        this.mappings = mappings == null ? List.of() : mappings;
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
        out.writeOptionalBoolean(isBuiltIn);
        out.writeString(name);
        out.writeString(description);
        out.writeCollection(mappings);
    }

    @Override
    public String toString() {
        return name;
    }

    public static class Mapping implements Writeable {

        private String rawField;
        private String ecs;
        private String ocsf;

        public Mapping(StreamInput sin) throws IOException {
            this.rawField = sin.readString();
            this.ecs = sin.readOptionalString();
            this.ocsf = sin.readOptionalString();
        }

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

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(rawField);
            out.writeOptionalString(ecs);
            out.writeOptionalString(ocsf);
        }

        public static Mapping readFrom(StreamInput sin) throws IOException {
            return new Mapping(sin);
        }
    }

}