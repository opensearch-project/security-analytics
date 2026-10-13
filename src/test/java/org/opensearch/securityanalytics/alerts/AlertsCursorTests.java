/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.test.OpenSearchTestCase;

public class AlertsCursorTests extends OpenSearchTestCase {

    private static final Table START_TIME_DESC = new Table("desc", "start_time", null, 20, 0, null);
    private static final Table SEVERITY_ASC = new Table("asc", "severity", null, 20, 0, null);

    private static final Object[] START_TIME_SORT_VALUES = new Object[] { 1700000000000L, ".opensearch-sap-windows-alerts", "m1", 7L };
    private static final Object[] SEVERITY_SORT_VALUES = new Object[] { "1", 1700000000000L, ".opensearch-sap-windows-alerts", "m1", 7L };

    public void testEncodeDecode() {
        String cursor = AlertsCursor.encode(START_TIME_DESC, START_TIME_SORT_VALUES);
        assertTrue(cursor, cursor.matches("^[A-Za-z0-9_-]+$"));
        AlertsCursor decoded = AlertsCursor.decode(cursor, START_TIME_DESC);
        assertArrayEquals(START_TIME_SORT_VALUES, decoded.getSortValues());
        assertEquals("start_time", decoded.getSortString());
        assertEquals("desc", decoded.getSortOrder());
        assertNull(decoded.getMissing());
        // the sort order is case-insensitive, like the request's
        assertArrayEquals(START_TIME_SORT_VALUES,
                AlertsCursor.decode(cursor, new Table("DESC", "start_time", null, 5, 0, "search")).getSortValues());

        String severityCursor = AlertsCursor.encode(SEVERITY_ASC, SEVERITY_SORT_VALUES);
        assertArrayEquals(SEVERITY_SORT_VALUES, AlertsCursor.decode(severityCursor, SEVERITY_ASC).getSortValues());
        // a missing keyword value is null, a missing date is a long
        Object[] missing = new Object[] { null, Long.MAX_VALUE, "index", null, 0L };
        assertArrayEquals(missing, AlertsCursor.decode(AlertsCursor.encode(SEVERITY_ASC, missing), SEVERITY_ASC).getSortValues());
        // small numbers are decoded as longs too
        Object[] small = new Object[] { 1L, "index", "m", 0L };
        assertArrayEquals(small, AlertsCursor.decode(AlertsCursor.encode(START_TIME_DESC, small), START_TIME_DESC).getSortValues());
    }

    public void testEncodedJson() {
        String cursor = AlertsCursor.encode(new Table("asc", "state", "_first", 20, 0, null), SEVERITY_SORT_VALUES);
        String json = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
        assertEquals("{\"v\":1,\"f\":\"state\",\"o\":\"asc\",\"m\":\"_first\",\"k\":[\"1\",1700000000000,"
                + "\".opensearch-sap-windows-alerts\",\"m1\",7]}", json);
    }

    public void testDecode_sortMismatch() {
        String cursor = AlertsCursor.encode(START_TIME_DESC, START_TIME_SORT_VALUES);
        assertInvalid(cursor, new Table("asc", "start_time", null, 20, 0, null), "not of the requested sort");
        assertInvalid(cursor, new Table("desc", "severity", null, 20, 0, null), "not of the requested sort");
        assertInvalid(cursor, new Table("desc", "start_time", "_first", 20, 0, null), "not of the requested sort");
        String withMissing = AlertsCursor.encode(new Table("asc", "severity", "_first", 20, 0, null), SEVERITY_SORT_VALUES);
        assertInvalid(withMissing, SEVERITY_ASC, "not of the requested sort");
        // a blank missing value is no missing value
        assertArrayEquals(START_TIME_SORT_VALUES,
                AlertsCursor.decode(cursor, new Table("desc", "start_time", " ", 20, 0, null)).getSortValues());
    }

    public void testDecode_wrongSortValues() {
        // arity
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, SEVERITY_SORT_VALUES), START_TIME_DESC, "has 5 sort values, expected 4");
        assertInvalid(AlertsCursor.encode(SEVERITY_ASC, START_TIME_SORT_VALUES), SEVERITY_ASC, "has 4 sort values, expected 5");
        assertInvalid(AlertsCursor.encode(SEVERITY_ASC, new Object[0]), SEVERITY_ASC, "has 0 sort values, expected 5");
        // types
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, new Object[] { "1700000000000", "index", "m1", 7L }), START_TIME_DESC,
                "invalid sort value at position 0, expected a number");
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, new Object[] { 1.5d, "index", "m1", 7L }), START_TIME_DESC,
                "invalid sort value at position 0, expected a number");
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, new Object[] { null, "index", "m1", 7L }), START_TIME_DESC,
                "invalid sort value at position 0, expected a number");
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, new Object[] { 1L, null, "m1", 7L }), START_TIME_DESC,
                "invalid sort value at position 1, expected a string");
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, new Object[] { 1L, "index", 5L, 7L }), START_TIME_DESC,
                "invalid sort value at position 2, expected a string or null");
        assertInvalid(AlertsCursor.encode(START_TIME_DESC, new Object[] { 1L, "index", "m1", "7" }), START_TIME_DESC,
                "invalid sort value at position 3, expected a number");
        assertInvalid(AlertsCursor.encode(SEVERITY_ASC, new Object[] { 1L, 1L, "index", "m1", 7L }), SEVERITY_ASC,
                "invalid sort value at position 0, expected a string or null");
        assertInvalid(AlertsCursor.encode(SEVERITY_ASC, new Object[] { "1", true, "index", "m1", 7L }), SEVERITY_ASC,
                "invalid sort value at position 1, expected a number");
    }

    public void testDecode_tampered() {
        String cursor = AlertsCursor.encode(START_TIME_DESC, START_TIME_SORT_VALUES);
        assertInvalid("", START_TIME_DESC, "searchAfter must not be empty");
        assertInvalid(cursor + "=", START_TIME_DESC, "not a valid cursor");
        assertInvalid(cursor.substring(0, cursor.length() - 3), START_TIME_DESC, "not a valid cursor");
        assertInvalid("not a cursor", START_TIME_DESC, "not a valid cursor");
        assertInvalid("a+b/c", START_TIME_DESC, "not a valid cursor");
        assertInvalid("A", START_TIME_DESC, "not a valid cursor");
        char[] tooLong = new char[AlertsCursor.MAX_LENGTH + 1];
        Arrays.fill(tooLong, 'A');
        assertInvalid(new String(tooLong), START_TIME_DESC, "not a valid cursor");

        assertInvalid(json("[1,2,3]"), START_TIME_DESC, "not a valid cursor");
        assertInvalid(json("\"cursor\""), START_TIME_DESC, "not a valid cursor");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",7]"), START_TIME_DESC,
                "not a valid cursor");
        assertInvalid(json("{\"v\":2,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",7]}"), START_TIME_DESC,
                "unsupported version");
        assertInvalid(json("{\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",7]}"), START_TIME_DESC,
                "unsupported version");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"k\":[1,\"i\",\"m\",7]}"), START_TIME_DESC,
                "not a valid cursor");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",7],\"x\":1}"), START_TIME_DESC,
                "not a valid cursor");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":{}}"), START_TIME_DESC, "not a valid cursor");
        assertInvalid(json("{\"v\":1,\"f\":1,\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",7]}"), START_TIME_DESC, "not a valid cursor");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":5,\"k\":[1,\"i\",\"m\",7]}"), START_TIME_DESC,
                "not a valid cursor");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",[7]]}"), START_TIME_DESC,
                "invalid sort value at position 3");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",{\"a\":1},7]}"), START_TIME_DESC,
                "invalid sort value at position 2");
        assertInvalid(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[123456789012345678901234567890,\"i\",\"m\",7]}"),
                START_TIME_DESC, "invalid sort value at position 0");
        // a valid hand-made cursor is accepted: it only positions the page, the request's filters still apply
        assertArrayEquals(new Object[] { 1L, "i", "m", 7L },
                AlertsCursor.decode(json("{\"v\":1,\"f\":\"start_time\",\"o\":\"desc\",\"m\":null,\"k\":[1,\"i\",\"m\",7]}"),
                        START_TIME_DESC).getSortValues());
    }

    private static String json(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertInvalid(String cursor, Table table, String expectedMessage) {
        IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> AlertsCursor.decode(cursor, table));
        assertTrue(e.getMessage(), e.getMessage().contains(expectedMessage));
    }
}
