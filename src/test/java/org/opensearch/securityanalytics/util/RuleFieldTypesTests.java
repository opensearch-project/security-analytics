/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.test.OpenSearchTestCase;

public class RuleFieldTypesTests extends OpenSearchTestCase {

    public void testConcreteFieldsAndMultifields() {
        Map<String, Object> mapping = Map.of(
            "properties",
            Map.of(
                "message", Map.of("type", "text", "fields", Map.of("keyword", Map.of("type", "keyword"))),
                "user", Map.of("properties", Map.of("name", Map.of("type", "wildcard"))),
                "events", Map.of("type", "nested", "properties", Map.of("code", Map.of("type", "long"))),
                "details", Map.of("type", "object", "properties", Map.of("enabled", Map.of("type", "boolean")))
            )
        );

        assertEquals(
            Map.of(
                "message", "text",
                "message.keyword", "keyword",
                "user.name", "wildcard",
                "events", "nested",
                "events.code", "long",
                "details", "object",
                "details.enabled", "boolean"
            ),
            RuleFieldTypes.fromMapping(mapping)
        );
    }

    public void testDocWrapper() {
        Map<String, Object> mapping = Map.of("properties", Map.of("name", Map.of("type", "keyword")));
        assertEquals(RuleFieldTypes.fromMapping(mapping), RuleFieldTypes.fromMapping(Map.of("_doc", mapping)));
        assertEquals(
            Map.of("name", "keyword"),
            RuleFieldTypes.fromMapping(Map.of("_doc", mapping, "properties", mapping.get("properties")))
        );
    }

    public void testAliasesResolveAbsolutePathsAndMultifields() {
        Map<String, Object> mapping = Map.of(
            "properties",
            Map.of(
                "ecs", Map.of("properties", Map.of("name", Map.of("type", "alias", "path", "user.name.raw"))),
                "user", Map.of(
                    "properties", Map.of("name", Map.of("type", "text", "fields", Map.of("raw", Map.of("type", "keyword"))))
                ),
                "chain", Map.of("type", "alias", "path", "ecs.name"),
                "wildcard_alias", Map.of("type", "alias", "path", "command"),
                "command", Map.of("type", "wildcard")
            )
        );

        assertEquals(
            Map.of(
                "user.name", "text",
                "user.name.raw", "keyword",
                "ecs.name", "keyword",
                "chain", "keyword",
                "command", "wildcard",
                "wildcard_alias", "wildcard"
            ),
            RuleFieldTypes.fromMapping(mapping)
        );
    }

    public void testMissingAndCyclicAliasesAreOmitted() {
        Map<String, Object> mapping = Map.of(
            "properties",
            Map.of(
                "self", Map.of("type", "alias", "path", "self"),
                "first", Map.of("type", "alias", "path", "second"),
                "second", Map.of("type", "alias", "path", "first"),
                "into_cycle", Map.of("type", "alias", "path", "first"),
                "missing", Map.of("type", "alias", "path", "absent"),
                "no_path", Map.of("type", "alias"),
                "wrong_path", Map.of("type", "alias", "path", 42),
                "valid", Map.of("type", "keyword")
            )
        );

        assertEquals(Map.of("valid", "keyword"), RuleFieldTypes.fromMapping(mapping));
    }

    public void testLongAliasChainDoesNotUseRecursion() {
        Map<String, Object> properties = new HashMap<>();
        for (int i = 0; i < 10000; i++) {
            properties.put("alias" + i, Map.of("type", "alias", "path", "alias" + (i + 1)));
        }
        properties.put("alias10000", Map.of("type", "wildcard"));

        Map<String, String> types = RuleFieldTypes.fromMapping(Map.of("properties", properties));
        assertEquals(10001, types.size());
        assertEquals("wildcard", types.get("alias0"));
    }

    public void testEmptyAndMalformedMappings() {
        assertEquals(Map.of(), RuleFieldTypes.fromMapping(null));
        assertEquals(Map.of(), RuleFieldTypes.fromMapping(Map.of()));
        assertEquals(Map.of(), RuleFieldTypes.fromMapping(Map.of("_doc", Map.of())));
        assertEquals(Map.of(), RuleFieldTypes.fromMapping(Map.of("properties", "invalid")));
        assertEquals(
            Map.of(),
            RuleFieldTypes.fromMapping(Map.of("_meta", Map.of("properties", Map.of("not_a_field", Map.of("type", "keyword")))))
        );
        assertEquals(
            Map.of("valid", "keyword"),
            RuleFieldTypes.fromMapping(
                Map.of(
                    "properties",
                    Map.of("invalid", "invalid", "untyped", Map.of("type", 42), "valid", Map.of("type", "keyword", "fields", false))
                )
            )
        );
    }

    public void testResultIsIndependentOfInput() {
        Map<String, Object> mapping = Map.of("properties", Map.of("name", Map.of("type", "keyword")));
        Map<String, String> result = RuleFieldTypes.fromMapping(mapping);
        result.put("name", "text");
        assertEquals(Map.of("name", "keyword"), RuleFieldTypes.fromMapping(mapping));
    }

    public void testMergeCompatibleIndices() {
        Map<String, String> first = Map.of("command", "wildcard", "name", "keyword");
        Map<String, String> second = Map.of("command", "wildcard", "count", "long");
        Map<String, String> expected = Map.of("command", "wildcard", "name", "keyword", "count", "long");

        assertEquals(expected, RuleFieldTypes.merge(List.of(first, second)));
        assertEquals(expected, RuleFieldTypes.merge(List.of(second, first)));
        assertEquals(Map.of(), RuleFieldTypes.merge(List.of()));
    }

    public void testMergeRejectsWildcardConflictsInEitherOrder() {
        for (String otherType : List.of("keyword", "text", "long")) {
            Map<String, String> wildcard = Map.of("command", "wildcard");
            Map<String, String> other = Map.of("command", otherType);
            IllegalArgumentException exception = expectThrows(
                IllegalArgumentException.class,
                () -> RuleFieldTypes.merge(List.of(wildcard, other))
            );
            assertTrue(exception.getMessage().contains("command"));
            assertTrue(exception.getMessage().contains("wildcard"));
            assertTrue(exception.getMessage().contains(otherType));
            expectThrows(IllegalArgumentException.class, () -> RuleFieldTypes.merge(List.of(other, wildcard)));
        }
        expectThrows(
            IllegalArgumentException.class,
            () -> RuleFieldTypes.merge(List.of(Map.of("name", "keyword"), Map.of("name", "text"), Map.of("name", "wildcard")))
        );
    }

    public void testMergeRetainsFirstNonWildcardTypeForLegacyConflicts() {
        Map<String, String> first = Map.of("name", "keyword", "count", "long");
        Map<String, String> second = Map.of("name", "text", "count", "integer");

        assertEquals(first, RuleFieldTypes.merge(List.of(first, second)));
        assertEquals(second, RuleFieldTypes.merge(List.of(second, first)));
    }
}