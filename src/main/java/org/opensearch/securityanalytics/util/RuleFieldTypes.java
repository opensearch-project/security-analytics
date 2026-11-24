/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Resolves mapping field types used when compiling rule queries. */
public final class RuleFieldTypes {

    private RuleFieldTypes() {}

    /**
     * Returns dotted field paths and their concrete mapping types, including multifields and resolved aliases.
     * Accepts a mapping source with root properties or a legacy {@code _doc} wrapper. Fields without an explicit
     * type and aliases with missing targets or cycles are omitted. The input is not modified.
     *
     * @param mappingSource mapping source, or {@code null} when no mapping is available
     * @return a new map of field paths to types; alias entries contain the target type, never {@code alias}
     */
    public static Map<String, String> fromMapping(Map<String, Object> mappingSource) {
        Map<String, String> fieldTypes = new HashMap<>();
        if (mappingSource == null) {
            return fieldTypes;
        }
        Map<?, ?> root = mappingSource;
        if (!(root.get("properties") instanceof Map) && root.get("_doc") instanceof Map) {
            root = (Map<?, ?>) root.get("_doc");
        }
        Map<String, String> aliases = new HashMap<>();
        collectFields("", root.get("properties"), fieldTypes, aliases);
        Set<String> unresolved = new HashSet<>();
        for (String alias : aliases.keySet()) {
            resolveAlias(alias, aliases, fieldTypes, unresolved);
        }
        return fieldTypes;
    }

    private static void collectFields(String prefix, Object fields, Map<String, String> fieldTypes, Map<String, String> aliases) {
        if (!(fields instanceof Map)) {
            return;
        }
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) fields).entrySet()) {
            if (!(entry.getKey() instanceof String) || !(entry.getValue() instanceof Map)) {
                continue;
            }
            String field = prefix.isEmpty() ? (String) entry.getKey() : prefix + "." + entry.getKey();
            Map<?, ?> definition = (Map<?, ?>) entry.getValue();
            Object type = definition.get("type");
            if ("alias".equals(type)) {
                Object path = definition.get("path");
                if (path instanceof String && !((String) path).isEmpty()) {
                    aliases.put(field, (String) path);
                }
            } else if (type instanceof String && !((String) type).isEmpty()) {
                fieldTypes.put(field, (String) type);
            }
            collectFields(field, definition.get("properties"), fieldTypes, aliases);
            collectFields(field, definition.get("fields"), fieldTypes, aliases);
        }
    }

    private static void resolveAlias(String alias, Map<String, String> aliases, Map<String, String> fieldTypes, Set<String> unresolved) {
        Set<String> visited = new LinkedHashSet<>();
        String target = alias;
        while (!fieldTypes.containsKey(target)) {
            if (unresolved.contains(target) || !visited.add(target) || !aliases.containsKey(target)) {
                unresolved.addAll(visited);
                return;
            }
            target = aliases.get(target);
        }
        String type = fieldTypes.get(target);
        for (String path : visited) {
            fieldTypes.put(path, type);
        }
    }

    public static boolean isNumeric(String type) {
        return type != null && Set.of(
            "byte", "short", "integer", "long", "unsigned_long", "half_float", "float", "double", "scaled_float"
        ).contains(type);
    }

    /**
     * Merges resolved mappings from concrete indices. Missing fields do not conflict. Wildcard, numeric and IP
     * mappings conflict with types outside their respective families because typed query compilation differs.
     * All numeric mapping types are compatible for range compilation; concrete mappers retain coercion semantics.
     * Other conflicts (e.g. keyword/text) retain the first type for legacy behavior. Conflict diagnostics are
     * deterministic regardless of index or field iteration order.
     *
     * @param indexFieldTypes resolved field types for each concrete index
     * @return a new map containing the union of field types, retaining the first compatible type
     * @throws IllegalArgumentException if typed query mapping families conflict across indices
     */
    public static Map<String, String> merge(Iterable<Map<String, String>> indexFieldTypes) {
        Map<String, String> merged = new HashMap<>();
        Map<String, Set<String>> allTypes = new TreeMap<>();
        for (Map<String, String> fieldTypes : indexFieldTypes) {
            for (Map.Entry<String, String> entry : fieldTypes.entrySet()) {
                merged.putIfAbsent(entry.getKey(), entry.getValue());
                allTypes.computeIfAbsent(entry.getKey(), ignored -> new TreeSet<>()).add(entry.getValue());
            }
        }
        for (Map.Entry<String, Set<String>> entry : allTypes.entrySet()) {
            Set<String> types = entry.getValue();
            boolean conflict = types.size() > 1 && (types.contains("wildcard") || types.contains("ip")
                || (types.stream().anyMatch(RuleFieldTypes::isNumeric) && !types.stream().allMatch(RuleFieldTypes::isNumeric)));
            if (conflict) {
                throw new IllegalArgumentException("Conflicting mapping types for field [" + entry.getKey() + "]: " + types);
            }
        }
        return merged;
    }
}