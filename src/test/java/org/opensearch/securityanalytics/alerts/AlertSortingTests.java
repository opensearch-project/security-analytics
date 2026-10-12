/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.test.OpenSearchTestCase;

public class AlertSortingTests extends OpenSearchTestCase {

    public void testOnlySortableFieldsAreSupported() {
        assertEquals(List.of("start_time", "monitor_name.keyword", "state", "severity"), GetAlertsRequest.SORTABLE_FIELDS);
        for (String field : GetAlertsRequest.SORTABLE_FIELDS) {
            assertTrue(field, AlertSorting.isSupported(field));
            assertNotNull(AlertSorting.comparator(field, "asc", null));
            assertNotNull(AlertSorting.comparator(field, "desc", null));
        }
        for (String field : new String[] { "monitor_name", "id", "version", "error_message", "alert_history.timestamp", "end_time",
                "last_notification_time", "acknowledged_time", "trigger_name.keyword", "workflow_id", "monitor_id", "finding_ids.keyword",
                "schema_version", null }) {
            assertFalse(String.valueOf(field), AlertSorting.isSupported(field));
            expectThrows(IllegalArgumentException.class, () -> AlertSorting.comparator(field, "asc", null));
        }
    }

    public void testStartTimeOrder() {
        Alert a1 = alert("a1", 1000L, "1", Alert.State.ACTIVE, "m");
        Alert a2 = alert("a2", 2000L, "1", Alert.State.ACTIVE, "m");
        Alert a3 = alert("a3", 3000L, "1", Alert.State.ACTIVE, "m");
        assertEquals(List.of("a1", "a2", "a3"), sortedIds(List.of(a3, a1, a2), "start_time", "asc", null));
        assertEquals(List.of("a3", "a2", "a1"), sortedIds(List.of(a1, a3, a2), "start_time", "DESC", null));
    }

    public void testDatesCompareAsEpochMillis() {
        // dates are indexed with millisecond precision: alerts within the same millisecond tie
        Alert a = new AlertBuilder().startTime(Instant.ofEpochMilli(1000L).plusNanos(900_000)).build("a");
        Alert b = new AlertBuilder().startTime(Instant.ofEpochMilli(1000L).plusNanos(100_000)).build("b");
        assertEquals(0, AlertSorting.comparator("start_time", "asc", null).compare(a, b));
        assertEquals(0, AlertSorting.comparator("start_time", "desc", null).compare(a, b));
    }

    public void testKeywordFieldsCompareUtf8Bytes() {
        // U+FF5E sorts before U+1F600 in UTF-8 byte order, but after it in UTF-16 (String#compareTo) order
        Alert fullWidth = alert("fullWidth", 1000L, "～", Alert.State.ACTIVE, "～");
        Alert emoji = alert("emoji", 1000L, "😀", Alert.State.ACTIVE, "😀");
        Alert upper = alert("upper", 1000L, "Zeta", Alert.State.ACTIVE, "Zeta");
        Alert lower = alert("lower", 1000L, "alpha", Alert.State.ACTIVE, "alpha");
        // an empty string is a value (it is indexed), it sorts first
        Alert empty = alert("empty", 1000L, "", Alert.State.ACTIVE, "");
        for (String field : List.of("monitor_name.keyword", "severity")) {
            assertEquals(field, List.of("empty", "upper", "lower", "fullWidth", "emoji"),
                    sortedIds(List.of(emoji, lower, fullWidth, upper, empty), field, "asc", null));
            assertEquals(field, List.of("emoji", "fullWidth", "lower", "upper", "empty"),
                    sortedIds(List.of(lower, emoji, empty, upper, fullWidth), field, "desc", null));
        }
    }

    public void testSeverityAndStateOrder() {
        Alert s1 = alert("s1", 1000L, "1", Alert.State.COMPLETED, "m");
        Alert s3 = alert("s3", 1000L, "3", Alert.State.ACKNOWLEDGED, "m");
        Alert s5 = alert("s5", 1000L, "5", Alert.State.ACTIVE, "m");
        assertEquals(List.of("s1", "s3", "s5"), sortedIds(List.of(s5, s1, s3), "severity", "asc", null));
        assertEquals(List.of("s5", "s3", "s1"), sortedIds(List.of(s1, s5, s3), "severity", "desc", null));
        // keyword order of the state names: ACKNOWLEDGED < ACTIVE < COMPLETED
        assertEquals(List.of("s3", "s5", "s1"), sortedIds(List.of(s1, s5, s3), "state", "asc", null));
        assertEquals(List.of("s1", "s5", "s3"), sortedIds(List.of(s3, s1, s5), "state", "desc", null));
    }

    public void testKeywordLongerThanIgnoreAboveSortsAsMissing() {
        String longName = "a".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE + 1);
        String maxName = "b".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE);
        Alert tooLong = alert("tooLong", 1000L, "1", Alert.State.ACTIVE, longName);
        Alert maxLength = alert("maxLength", 1000L, "1", Alert.State.ACTIVE, maxName);
        Alert shortName = alert("shortName", 1000L, "1", Alert.State.ACTIVE, "c");
        assertEquals(List.of("maxLength", "shortName", "tooLong"), sortedIds(List.of(tooLong, shortName, maxLength), "monitor_name.keyword", "asc", null));
        assertEquals(List.of("shortName", "maxLength", "tooLong"), sortedIds(List.of(tooLong, maxLength, shortName), "monitor_name.keyword", "desc", null));
        // severity and state have no ignore_above: long values are values
        Alert longSeverity = alert("longSeverity", 1000L, longName, Alert.State.ACTIVE, "m");
        Alert severityB = alert("severityB", 1000L, "b", Alert.State.ACTIVE, "m");
        assertEquals(List.of("longSeverity", "severityB"), sortedIds(List.of(severityB, longSeverity), "severity", "asc", null));
    }

    public void testMissingValues() {
        // a monitor name longer than ignore_above is not indexed in monitor_name.keyword: the alert has no sort value
        Alert missing = alert("missing", 1000L, "1", Alert.State.ACTIVE, "x".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE + 1));
        Alert nameA = alert("nameA", 1000L, "1", Alert.State.ACTIVE, "a");
        Alert nameC = alert("nameC", 1000L, "1", Alert.State.ACTIVE, "c");
        // last by default, for both sort orders
        for (String missingParam : new String[] { null, "", "_last" }) {
            assertEquals(List.of("nameA", "nameC", "missing"), sortedIds(List.of(missing, nameC, nameA), "monitor_name.keyword", "asc", missingParam));
            assertEquals(List.of("nameC", "nameA", "missing"), sortedIds(List.of(missing, nameA, nameC), "monitor_name.keyword", "desc", missingParam));
        }
        assertEquals(List.of("missing", "nameA", "nameC"), sortedIds(List.of(nameC, missing, nameA), "monitor_name.keyword", "asc", "_first"));
        assertEquals(List.of("missing", "nameC", "nameA"), sortedIds(List.of(nameA, nameC, missing), "monitor_name.keyword", "desc", "_first"));
        // a custom missing value is compared like a value
        assertEquals(List.of("nameA", "missing", "nameC"), sortedIds(List.of(nameC, missing, nameA), "monitor_name.keyword", "asc", "b"));
        assertEquals(List.of("nameC", "missing", "nameA"), sortedIds(List.of(nameA, missing, nameC), "monitor_name.keyword", "desc", "b"));
        assertEquals(List.of("missing", "nameA", "nameC"), sortedIds(List.of(nameC, missing, nameA), "monitor_name.keyword", "asc", "0"));
        // a missing parameter does not change the order of alerts that have a value
        for (String field : List.of("start_time", "state", "severity")) {
            for (String missingParam : new String[] { null, "_first", "_last", "5" }) {
                assertEquals(0, AlertSorting.comparator(field, "asc", missingParam).compare(nameA, nameC));
            }
        }
    }

    public void testMergeSortedKeepsListOrderAndBreaksTiesByListPosition() {
        Comparator<Alert> comparator = AlertSorting.comparator("severity", "asc", null);
        List<Alert> first = List.of(alert("f1", 1L, "1", Alert.State.ACTIVE, "m"), alert("f2", 2L, "2", Alert.State.ACTIVE, "m"));
        List<Alert> second = List.of(alert("s1", 3L, "1", Alert.State.ACTIVE, "m"), alert("s2", 4L, "3", Alert.State.ACTIVE, "m"));
        List<Alert> merged = AlertSorting.mergeSorted(List.of(first, second), comparator, 10);
        assertEquals(List.of("f1", "s1", "f2", "s2"), merged.stream().map(Alert::getId).collect(Collectors.toList()));
        assertEquals(List.of("f1", "s1"), AlertSorting.mergeSorted(List.of(first, second), comparator, 2).stream().map(Alert::getId).collect(Collectors.toList()));
        assertEquals(List.of(), AlertSorting.mergeSorted(List.of(first, second), comparator, 0));
        assertEquals(List.of(), AlertSorting.mergeSorted(List.of(List.of(), List.of()), comparator, 5));
    }

    /**
     * Each log type returns only its top N alerts. Merging the top N of every list must give the same first N alerts
     * as merging the complete lists, for every page boundary, otherwise pages would overlap or have gaps.
     */
    public void testMergeOfTruncatedListsIsPrefixOfFullMerge() {
        for (int iteration = 0; iteration < 50; iteration++) {
            String sortString = randomFrom(GetAlertsRequest.SORTABLE_FIELDS);
            String sortOrder = randomFrom("asc", "desc");
            String missing = randomFrom(new String[] { null, "_first", "_last", "beta" });
            Comparator<Alert> comparator = AlertSorting.comparator(sortString, sortOrder, missing);
            int numLists = randomIntBetween(2, 4);
            List<List<Alert>> lists = new ArrayList<>();
            int total = 0;
            for (int l = 0; l < numLists; l++) {
                List<Alert> list = new ArrayList<>();
                int size = randomIntBetween(0, 15);
                for (int i = 0; i < size; i++) {
                    list.add(randomAlert("l" + l + "-" + i));
                }
                // OpenSearch returns each list sorted; List#sort is stable like a sort with a tie breaker
                list.sort(comparator);
                lists.add(list);
                total += size;
            }
            List<Alert> fullMerge = AlertSorting.mergeSorted(lists, comparator, Integer.MAX_VALUE);
            assertEquals(total, fullMerge.size());
            for (int i = 1; i < fullMerge.size(); i++) {
                assertTrue("merged alerts are not sorted", comparator.compare(fullMerge.get(i - 1), fullMerge.get(i)) <= 0);
            }
            assertEquals(lists.stream().flatMap(List::stream).map(Alert::getId).sorted().collect(Collectors.toList()),
                    fullMerge.stream().map(Alert::getId).sorted().collect(Collectors.toList()));

            for (int n = 0; n <= total + 1; n++) {
                int limit = n;
                List<List<Alert>> truncated = lists.stream().map(list -> list.subList(0, Math.min(limit, list.size()))).collect(Collectors.toList());
                assertEquals(fullMerge.subList(0, Math.min(n, total)), AlertSorting.mergeSorted(truncated, comparator, n));
            }
        }
    }

    private Alert randomAlert(String id) {
        return new AlertBuilder()
                .startTime(Instant.ofEpochMilli(randomLongBetween(0, 20) * 1000L))
                .severity(randomFrom("1", "2", "3", "4", "5"))
                .state(randomFrom(Alert.State.ACTIVE, Alert.State.ACKNOWLEDGED, Alert.State.COMPLETED))
                .monitorName(randomFrom("alpha", "Beta", "gamma", "a".repeat(300)))
                .build(id);
    }

    private static List<String> sortedIds(List<Alert> alerts, String sortString, String sortOrder, String missing) {
        List<Alert> sorted = new ArrayList<>(alerts);
        Collections.shuffle(sorted, random());
        sorted.sort(AlertSorting.comparator(sortString, sortOrder, missing));
        return sorted.stream().map(Alert::getId).collect(Collectors.toList());
    }

    static Alert alert(String id, long startTime, String severity, Alert.State state, String monitorName) {
        return alert(id, "monitor_id", startTime, severity, state, monitorName);
    }

    static Alert alert(String id, String monitorId, long startTime, String severity, Alert.State state, String monitorName) {
        return new AlertBuilder()
                .monitorId(monitorId)
                .startTime(Instant.ofEpochMilli(startTime))
                .severity(severity)
                .state(state)
                .monitorName(monitorName)
                .build(id);
    }

    static final class AlertBuilder {
        private String monitorId = "monitor_id";
        private String monitorName = "m";
        private Alert.State state = Alert.State.ACTIVE;
        private Instant startTime = Instant.ofEpochMilli(1000L);
        private String severity = "1";

        AlertBuilder monitorId(String value) { monitorId = value; return this; }
        AlertBuilder monitorName(String value) { monitorName = value; return this; }
        AlertBuilder state(Alert.State value) { state = value; return this; }
        AlertBuilder startTime(Instant value) { startTime = value; return this; }
        AlertBuilder severity(String value) { severity = value; return this; }

        Alert build(String id) {
            return new Alert(
                    id,
                    1L,
                    5,
                    monitorId,
                    "",
                    "",
                    monitorName,
                    1L,
                    null,
                    "trigger_id",
                    "t",
                    List.of(),
                    List.of(),
                    state,
                    startTime,
                    null,
                    null,
                    null,
                    null,
                    List.of(),
                    severity,
                    List.of(),
                    null,
                    null,
                    List.of(),
                    null
            );
        }
    }
}
