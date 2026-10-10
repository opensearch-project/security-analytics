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
            assertNotNull(AlertSorting.comparator(field, "asc", null));
            assertNotNull(AlertSorting.comparator(field, "desc", null));
        }
        expectThrows(IllegalArgumentException.class, () -> AlertSorting.comparator("monitor_name", "asc", null));
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
        return alert(
                id,
                randomLongBetween(0, 20) * 1000L,
                randomBoolean() ? null : randomLongBetween(0, 20) * 1000L,
                randomFrom("1", "2", "3", "4", "5"),
                randomFrom(Alert.State.ACTIVE, Alert.State.ACKNOWLEDGED, Alert.State.COMPLETED),
                randomFrom("alpha", "Beta", "gamma", "a".repeat(300)),
                randomFrom("t1", "T2", "t3", "t".repeat(300))
        );
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
                triggerName,
                List.of(),
                List.of(),
                state,
                Instant.ofEpochMilli(startTime),
                null,
                lastNotificationTime == null ? null : Instant.ofEpochMilli(lastNotificationTime),
                null,
                null,
                List.of(),
                severity,
                List.of(),
                null,
                null,
                List.of(),
                List.of()
        );
    }
}
