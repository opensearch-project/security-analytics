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

    public void testAllSortableFieldsAreSupported() {
        for (String field : GetAlertsRequest.SORTABLE_FIELDS) {
            assertTrue(field, AlertSorting.isSupported(field));
            assertNotNull(AlertSorting.comparator(field, "asc", null));
            assertNotNull(AlertSorting.comparator(field, "desc", null));
        }
        for (String field : new String[] { "monitor_name", "id", "version", "error_message", "alert_history.timestamp", null }) {
            assertFalse(String.valueOf(field), AlertSorting.isSupported(field));
            expectThrows(IllegalArgumentException.class, () -> AlertSorting.comparator(field, "asc", null));
        }
    }

    public void testDateFields() {
        for (String field : List.of("end_time", "acknowledged_time")) {
            AlertBuilder base = new AlertBuilder();
            Alert early = (field.equals("end_time") ? base.endTime(1000L) : base.acknowledgedTime(1000L)).build("early");
            Alert late = (field.equals("end_time") ? new AlertBuilder().endTime(9000L) : new AlertBuilder().acknowledgedTime(9000L)).build("late");
            Alert missing = new AlertBuilder().build("missing");
            assertEquals(List.of("early", "late", "missing"), sortedIds(List.of(late, missing, early), field, "asc", null));
            assertEquals(List.of("late", "early", "missing"), sortedIds(List.of(early, missing, late), field, "desc", null));
            assertEquals(List.of("missing", "early", "late"), sortedIds(List.of(late, missing, early), field, "asc", "_first"));
            // a custom missing value is epoch millis
            assertEquals(List.of("early", "missing", "late"), sortedIds(List.of(late, missing, early), field, "asc", "5000"));
            assertEquals(List.of("late", "missing", "early"), sortedIds(List.of(early, missing, late), field, "desc", "5000"));
            assertEquals(List.of("missing", "early", "late"), sortedIds(List.of(late, missing, early), field, "asc", "-1"));
        }
    }

    public void testDatesCompareAsEpochMillis() {
        // dates are indexed with millisecond precision: alerts within the same millisecond tie
        Alert a = new AlertBuilder().startTime(Instant.ofEpochMilli(1000L).plusNanos(900_000)).build("a");
        Alert b = new AlertBuilder().startTime(Instant.ofEpochMilli(1000L).plusNanos(100_000)).build("b");
        assertEquals(0, AlertSorting.comparator("start_time", "asc", null).compare(a, b));
        assertEquals(0, AlertSorting.comparator("start_time", "desc", null).compare(a, b));
    }

    public void testNumericFieldsCompareNumerically() {
        Alert v2 = new AlertBuilder().schemaVersion(2).monitorVersion(2L).build("v2");
        Alert v10 = new AlertBuilder().schemaVersion(10).monitorVersion(10L).build("v10");
        Alert v9 = new AlertBuilder().schemaVersion(9).monitorVersion(9L).build("v9");
        Alert negative = new AlertBuilder().schemaVersion(-1).monitorVersion(-1L).build("negative");
        for (String field : List.of("schema_version", "monitor_version")) {
            assertEquals(List.of("negative", "v2", "v9", "v10"), sortedIds(List.of(v10, v2, negative, v9), field, "asc", null));
            assertEquals(List.of("v10", "v9", "v2", "negative"), sortedIds(List.of(v2, v9, negative, v10), field, "desc", null));
        }
        // monitor_version is a long
        Alert big = new AlertBuilder().monitorVersion(Long.MAX_VALUE).build("big");
        assertEquals(List.of("v9", "big"), sortedIds(List.of(big, v9), "monitor_version", "asc", null));
    }

    public void testKeywordFields() {
        Alert upper = new AlertBuilder().monitorId("Zeta").triggerId("Zeta").executionId("Zeta").workflowId("Zeta").workflowName("Zeta").build("upper");
        Alert lower = new AlertBuilder().monitorId("alpha").triggerId("alpha").executionId("alpha").workflowId("alpha").workflowName("alpha").build("lower");
        Alert emoji = new AlertBuilder().monitorId("😀").triggerId("😀").executionId("😀").workflowId("😀").workflowName("😀").build("emoji");
        Alert fullWidth = new AlertBuilder().monitorId("～").triggerId("～").executionId("～").workflowId("～").workflowName("～").build("fullWidth");
        // an empty string is a value (it is indexed), it sorts first
        Alert empty = new AlertBuilder().monitorId("").triggerId("").executionId("").workflowId("").workflowName("").build("empty");
        for (String field : List.of("monitor_id", "trigger_id", "execution_id", "workflow_id", "workflow_name")) {
            assertEquals(field, List.of("empty", "upper", "lower", "fullWidth", "emoji"),
                    sortedIds(List.of(emoji, lower, fullWidth, upper, empty), field, "asc", null));
            assertEquals(field, List.of("emoji", "fullWidth", "lower", "upper", "empty"),
                    sortedIds(List.of(lower, emoji, empty, upper, fullWidth), field, "desc", null));
        }
        // keywords without ignore_above: long values are values
        String longValue = "a".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE + 10);
        Alert longId = new AlertBuilder().monitorId(longValue).build("long");
        Alert shortId = new AlertBuilder().monitorId("b").build("short");
        assertEquals(List.of("long", "short"), sortedIds(List.of(shortId, longId), "monitor_id", "asc", null));
        // execution_id is optional
        Alert noExecution = new AlertBuilder().executionId(null).build("noExecution");
        assertEquals(List.of("upper", "lower", "noExecution"), sortedIds(List.of(noExecution, lower, upper), "execution_id", "asc", null));
        assertEquals(List.of("lower", "upper", "noExecution"), sortedIds(List.of(noExecution, upper, lower), "execution_id", "desc", null));
        assertEquals(List.of("noExecution", "upper", "lower"), sortedIds(List.of(lower, noExecution, upper), "execution_id", "asc", "_first"));
        assertEquals(List.of("upper", "noExecution", "lower"), sortedIds(List.of(lower, noExecution, upper), "execution_id", "asc", "Zz"));
    }

    /** Multi-valued fields sort on their smallest value in ascending, on their largest value in descending order. */
    public void testMultiValuedKeywordFields() {
        Alert ad = new AlertBuilder().findingIds(List.of("d", "a")).relatedDocIds(List.of("d", "a"))
                .associatedAlertIds(List.of("d", "a")).clusters(List.of("d", "a")).build("ad");
        Alert bc = new AlertBuilder().findingIds(List.of("b", "c")).relatedDocIds(List.of("b", "c"))
                .associatedAlertIds(List.of("b", "c")).clusters(List.of("b", "c")).build("bc");
        Alert e = new AlertBuilder().findingIds(List.of("e")).relatedDocIds(List.of("e"))
                .associatedAlertIds(List.of("e")).clusters(List.of("e")).build("e");
        Alert none = new AlertBuilder().findingIds(List.of()).relatedDocIds(List.of())
                .associatedAlertIds(List.of()).clusters(null).build("none");
        for (String field : List.of("finding_ids.keyword", "related_doc_ids.keyword", "associated_alert_ids.keyword", "clusters.keyword")) {
            assertEquals(field, List.of("ad", "bc", "e", "none"), sortedIds(List.of(none, e, bc, ad), field, "asc", null));
            assertEquals(field, List.of("e", "ad", "bc", "none"), sortedIds(List.of(bc, none, ad, e), field, "desc", null));
            assertEquals(field, List.of("none", "e", "ad", "bc"), sortedIds(List.of(bc, none, ad, e), field, "desc", "_first"));
            // a custom missing value is compared like a value
            assertEquals(field, List.of("ad", "bc", "none", "e"), sortedIds(List.of(none, e, bc, ad), field, "asc", "bb"));
        }
    }

    public void testStartTimeOrder() {
        Alert a1 = alert("a1", 1000L, null, "1", Alert.State.ACTIVE, "m", "t");
        Alert a2 = alert("a2", 2000L, null, "1", Alert.State.ACTIVE, "m", "t");
        Alert a3 = alert("a3", 3000L, null, "1", Alert.State.ACTIVE, "m", "t");
        assertEquals(List.of("a1", "a2", "a3"), sortedIds(List.of(a3, a1, a2), "start_time", "asc", null));
        assertEquals(List.of("a3", "a2", "a1"), sortedIds(List.of(a1, a3, a2), "start_time", "DESC", null));
    }

    public void testKeywordFieldsCompareUtf8Bytes() {
        // U+FF5E sorts before U+1F600 in UTF-8 byte order, but after it in UTF-16 (String#compareTo) order
        Alert fullWidth = alert("fullWidth", 1000L, null, "1", Alert.State.ACTIVE, "～", "～");
        Alert emoji = alert("emoji", 1000L, null, "1", Alert.State.ACTIVE, "😀", "😀");
        Alert upper = alert("upper", 1000L, null, "1", Alert.State.ACTIVE, "Zeta", "Zeta");
        Alert lower = alert("lower", 1000L, null, "1", Alert.State.ACTIVE, "alpha", "alpha");
        for (String field : List.of("monitor_name.keyword", "trigger_name.keyword")) {
            assertEquals(List.of("upper", "lower", "fullWidth", "emoji"), sortedIds(List.of(emoji, lower, fullWidth, upper), field, "asc", null));
            assertEquals(List.of("emoji", "fullWidth", "lower", "upper"), sortedIds(List.of(lower, emoji, upper, fullWidth), field, "desc", null));
        }
    }

    public void testSeverityAndStateOrder() {
        Alert s1 = alert("s1", 1000L, null, "1", Alert.State.COMPLETED, "m", "t");
        Alert s3 = alert("s3", 1000L, null, "3", Alert.State.ACKNOWLEDGED, "m", "t");
        Alert s5 = alert("s5", 1000L, null, "5", Alert.State.ACTIVE, "m", "t");
        assertEquals(List.of("s1", "s3", "s5"), sortedIds(List.of(s5, s1, s3), "severity", "asc", null));
        assertEquals(List.of("s5", "s3", "s1"), sortedIds(List.of(s1, s5, s3), "severity", "desc", null));
        // keyword order of the state names: ACKNOWLEDGED < ACTIVE < COMPLETED
        assertEquals(List.of("s3", "s5", "s1"), sortedIds(List.of(s1, s5, s3), "state", "asc", null));
        assertEquals(List.of("s1", "s5", "s3"), sortedIds(List.of(s3, s1, s5), "state", "desc", null));
    }

    public void testMissingValuesAreLastByDefaultForBothOrders() {
        Alert missing = alert("missing", 1000L, null, "1", Alert.State.ACTIVE, "m", "t");
        Alert early = alert("early", 1000L, 1000L, "1", Alert.State.ACTIVE, "m", "t");
        Alert late = alert("late", 1000L, 5000L, "1", Alert.State.ACTIVE, "m", "t");
        for (String missingParam : new String[] { null, "", "_last" }) {
            assertEquals(List.of("early", "late", "missing"), sortedIds(List.of(missing, late, early), "last_notification_time", "asc", missingParam));
            assertEquals(List.of("late", "early", "missing"), sortedIds(List.of(missing, early, late), "last_notification_time", "desc", missingParam));
        }
        assertEquals(List.of("missing", "early", "late"), sortedIds(List.of(late, missing, early), "last_notification_time", "asc", "_first"));
        assertEquals(List.of("missing", "late", "early"), sortedIds(List.of(early, late, missing), "last_notification_time", "desc", "_first"));
        // custom missing value: epoch millis
        assertEquals(List.of("early", "missing", "late"), sortedIds(List.of(late, missing, early), "last_notification_time", "asc", "3000"));
        assertEquals(List.of("late", "missing", "early"), sortedIds(List.of(early, missing, late), "last_notification_time", "desc", "3000"));
        // custom missing value: keyword (a trigger name longer than ignore_above is not indexed in trigger_name.keyword)
        Alert noTrigger = alert("noTrigger", 1000L, null, "1", Alert.State.ACTIVE, "m", "x".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE + 1));
        Alert triggerA = alert("triggerA", 1000L, null, "1", Alert.State.ACTIVE, "m", "a");
        Alert triggerC = alert("triggerC", 1000L, null, "1", Alert.State.ACTIVE, "m", "c");
        assertEquals(List.of("triggerA", "noTrigger", "triggerC"), sortedIds(List.of(triggerC, noTrigger, triggerA), "trigger_name.keyword", "asc", "b"));
    }

    public void testKeywordLongerThanIgnoreAboveSortsAsMissing() {
        String longName = "a".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE + 1);
        String maxName = "b".repeat(AlertSorting.KEYWORD_IGNORE_ABOVE);
        Alert tooLong = alert("tooLong", 1000L, null, "1", Alert.State.ACTIVE, longName, "t");
        Alert maxLength = alert("maxLength", 1000L, null, "1", Alert.State.ACTIVE, maxName, "t");
        Alert shortName = alert("shortName", 1000L, null, "1", Alert.State.ACTIVE, "c", "t");
        assertEquals(List.of("maxLength", "shortName", "tooLong"), sortedIds(List.of(tooLong, shortName, maxLength), "monitor_name.keyword", "asc", null));
        assertEquals(List.of("shortName", "maxLength", "tooLong"), sortedIds(List.of(tooLong, maxLength, shortName), "monitor_name.keyword", "desc", null));
    }

    public void testMergeSortedKeepsListOrderAndBreaksTiesByListPosition() {
        Comparator<Alert> comparator = AlertSorting.comparator("severity", "asc", null);
        List<Alert> first = List.of(alert("f1", 1L, null, "1", Alert.State.ACTIVE, "m", "t"), alert("f2", 2L, null, "2", Alert.State.ACTIVE, "m", "t"));
        List<Alert> second = List.of(alert("s1", 3L, null, "1", Alert.State.ACTIVE, "m", "t"), alert("s2", 4L, null, "3", Alert.State.ACTIVE, "m", "t"));
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
            String missing = randomFrom(new String[] { null, "_first", "_last" });
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
                .lastNotificationTime(randomBoolean() ? null : randomLongBetween(0, 20) * 1000L)
                .endTime(randomBoolean() ? null : randomLongBetween(0, 20) * 1000L)
                .acknowledgedTime(randomBoolean() ? null : randomLongBetween(0, 20) * 1000L)
                .severity(randomFrom("1", "2", "3", "4", "5"))
                .state(randomFrom(Alert.State.ACTIVE, Alert.State.ACKNOWLEDGED, Alert.State.COMPLETED))
                .monitorName(randomFrom("alpha", "Beta", "gamma", "a".repeat(300)))
                .triggerName(randomFrom("t1", "T2", "t3", "t".repeat(300)))
                .monitorId(randomFrom("m1", "M2", "m3", ""))
                .triggerId(randomFrom("t1", "T2", "t3"))
                .executionId(randomFrom("e1", "E2", null))
                .workflowId(randomFrom("w1", "W2", ""))
                .workflowName(randomFrom("n1", "N2", ""))
                .schemaVersion(randomIntBetween(-1, 12))
                .monitorVersion(randomLongBetween(-1, 12))
                .findingIds(randomSubsetOf(List.of("f1", "F2", "f3", "f4")))
                .relatedDocIds(randomSubsetOf(List.of("d1", "D2", "d3")))
                .associatedAlertIds(randomSubsetOf(List.of("a1", "A2", "a3")))
                .clusters(randomBoolean() ? null : randomSubsetOf(List.of("c1", "C2", "c3")))
                .build(id);
    }

    private static List<String> sortedIds(List<Alert> alerts, String sortString, String sortOrder, String missing) {
        List<Alert> sorted = new ArrayList<>(alerts);
        Collections.shuffle(sorted, random());
        sorted.sort(AlertSorting.comparator(sortString, sortOrder, missing));
        return sorted.stream().map(Alert::getId).collect(Collectors.toList());
    }

    static Alert alert(String id, long startTime, Long lastNotificationTime, String severity, Alert.State state, String monitorName, String triggerName) {
        return alert(id, "monitor_id", startTime, lastNotificationTime, severity, state, monitorName, triggerName);
    }

    static Alert alert(String id, String monitorId, long startTime, Long lastNotificationTime, String severity, Alert.State state,
                       String monitorName, String triggerName) {
        return new AlertBuilder()
                .monitorId(monitorId)
                .startTime(Instant.ofEpochMilli(startTime))
                .lastNotificationTime(lastNotificationTime)
                .severity(severity)
                .state(state)
                .monitorName(monitorName)
                .triggerName(triggerName)
                .build(id);
    }

    static final class AlertBuilder {
        private int schemaVersion = 5;
        private String monitorId = "monitor_id";
        private String workflowId = "";
        private String workflowName = "";
        private String monitorName = "m";
        private long monitorVersion = 1L;
        private String triggerId = "trigger_id";
        private String triggerName = "t";
        private List<String> findingIds = List.of();
        private List<String> relatedDocIds = List.of();
        private Alert.State state = Alert.State.ACTIVE;
        private Instant startTime = Instant.ofEpochMilli(1000L);
        private Long endTime;
        private Long lastNotificationTime;
        private Long acknowledgedTime;
        private String severity = "1";
        private String executionId;
        private List<String> associatedAlertIds = List.of();
        private List<String> clusters;

        AlertBuilder schemaVersion(int value) { schemaVersion = value; return this; }
        AlertBuilder monitorId(String value) { monitorId = value; return this; }
        AlertBuilder workflowId(String value) { workflowId = value; return this; }
        AlertBuilder workflowName(String value) { workflowName = value; return this; }
        AlertBuilder monitorName(String value) { monitorName = value; return this; }
        AlertBuilder monitorVersion(long value) { monitorVersion = value; return this; }
        AlertBuilder triggerId(String value) { triggerId = value; return this; }
        AlertBuilder triggerName(String value) { triggerName = value; return this; }
        AlertBuilder findingIds(List<String> value) { findingIds = value; return this; }
        AlertBuilder relatedDocIds(List<String> value) { relatedDocIds = value; return this; }
        AlertBuilder state(Alert.State value) { state = value; return this; }
        AlertBuilder startTime(Instant value) { startTime = value; return this; }
        AlertBuilder endTime(Long value) { endTime = value; return this; }
        AlertBuilder lastNotificationTime(Long value) { lastNotificationTime = value; return this; }
        AlertBuilder acknowledgedTime(Long value) { acknowledgedTime = value; return this; }
        AlertBuilder severity(String value) { severity = value; return this; }
        AlertBuilder executionId(String value) { executionId = value; return this; }
        AlertBuilder associatedAlertIds(List<String> value) { associatedAlertIds = value; return this; }
        AlertBuilder clusters(List<String> value) { clusters = value; return this; }

        Alert build(String id) {
            return new Alert(
                    id,
                    1L,
                    schemaVersion,
                    monitorId,
                    workflowId,
                    workflowName,
                    monitorName,
                    monitorVersion,
                    null,
                    triggerId,
                    triggerName,
                    findingIds,
                    relatedDocIds,
                    state,
                    startTime,
                    endTime == null ? null : Instant.ofEpochMilli(endTime),
                    lastNotificationTime == null ? null : Instant.ofEpochMilli(lastNotificationTime),
                    acknowledgedTime == null ? null : Instant.ofEpochMilli(acknowledgedTime),
                    null,
                    List.of(),
                    severity,
                    List.of(),
                    null,
                    executionId,
                    associatedAlertIds,
                    clusters
            );
        }
    }
}
