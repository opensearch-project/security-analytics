/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.alerts;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import org.apache.lucene.util.BytesRef;
import org.opensearch.commons.alerting.model.Alert;

/**
 * Merges alert pages that were fetched (and sorted by OpenSearch) from several alert indices into a single sorted page.
 * <p>
 * The comparator mirrors OpenSearch's field sort semantics for the sortable alert fields
 * ({@link org.opensearch.securityanalytics.action.GetAlertsRequest#SORTABLE_FIELDS}): dates compare chronologically,
 * keywords compare by their UTF-8 bytes, keyword sub-fields ignore values longer than {@code ignore_above} (256 in
 * Alerting's alert mapping) and missing values are placed according to the {@code missing} parameter
 * ({@code _last} by default, for both sort orders).
 */
public final class AlertSorting {

    /** ignore_above of the monitor_name.keyword and trigger_name.keyword sub-fields in Alerting's alert mapping */
    static final int KEYWORD_IGNORE_ABOVE = 256;

    private static final String MISSING_FIRST = "_first";
    private static final String MISSING_LAST = "_last";

    private AlertSorting() {
    }

    /**
     * @param sortString one of {@link org.opensearch.securityanalytics.action.GetAlertsRequest#SORTABLE_FIELDS}
     * @param sortOrder  asc or desc (case-insensitive)
     * @param missing    the Table's missing parameter: null/blank or _last, _first, or a custom value
     */
    public static Comparator<Alert> comparator(String sortString, String sortOrder, String missing) {
        boolean descending = "desc".equalsIgnoreCase(sortOrder);
        Function<Alert, Comparable<?>> sortValue;
        Function<String, Comparable<?>> parseMissing;
        switch (sortString) {
            case "start_time":
                sortValue = Alert::getStartTime;
                parseMissing = AlertSorting::parseEpochMillis;
                break;
            case "last_notification_time":
                sortValue = Alert::getLastNotificationTime;
                parseMissing = AlertSorting::parseEpochMillis;
                break;
            case "severity":
                sortValue = alert -> keyword(alert.getSeverity(), Integer.MAX_VALUE);
                parseMissing = value -> new BytesRef(value);
                break;
            case "state":
                sortValue = alert -> alert.getState() == null ? null : keyword(alert.getState().name(), Integer.MAX_VALUE);
                parseMissing = value -> new BytesRef(value);
                break;
            case "monitor_name.keyword":
                sortValue = alert -> keyword(alert.getMonitorName(), KEYWORD_IGNORE_ABOVE);
                parseMissing = value -> new BytesRef(value);
                break;
            case "trigger_name.keyword":
                sortValue = alert -> keyword(alert.getTriggerName(), KEYWORD_IGNORE_ABOVE);
                parseMissing = value -> new BytesRef(value);
                break;
            default:
                throw new IllegalArgumentException(String.format(Locale.ROOT, "sorting alerts on [%s] is not supported", sortString));
        }

        boolean missingFirst = MISSING_FIRST.equals(missing);
        Comparable<?> missingValue = missing == null || missing.isBlank() || MISSING_FIRST.equals(missing) || MISSING_LAST.equals(missing)
                ? null
                : parseMissing.apply(missing);

        return (a, b) -> {
            Comparable<?> va = sortValue.apply(a);
            Comparable<?> vb = sortValue.apply(b);
            if (va == null) {
                va = missingValue;
            }
            if (vb == null) {
                vb = missingValue;
            }
            if (va == null || vb == null) {
                if (va == vb) {
                    return 0;
                }
                // a missing value is placed first or last independently of the sort order
                return (va == null) == missingFirst ? -1 : 1;
            }
            @SuppressWarnings("unchecked")
            int result = ((Comparable<Object>) va).compareTo(vb);
            return descending ? -result : result;
        };
    }

    /**
     * Merges lists that are each sorted according to {@code comparator}, keeping the relative order of every list.
     * Ties between lists are broken by list position, which keeps the merged order deterministic across pages.
     *
     * @param limit maximum number of elements to return
     */
    public static <T> List<T> mergeSorted(List<List<T>> sortedLists, Comparator<? super T> comparator, int limit) {
        int[] positions = new int[sortedLists.size()];
        List<T> merged = new ArrayList<>();
        while (merged.size() < limit) {
            int best = -1;
            for (int i = 0; i < sortedLists.size(); i++) {
                if (positions[i] < sortedLists.get(i).size()
                        && (best == -1 || comparator.compare(sortedLists.get(i).get(positions[i]), sortedLists.get(best).get(positions[best])) < 0)) {
                    best = i;
                }
            }
            if (best == -1) {
                break;
            }
            merged.add(sortedLists.get(best).get(positions[best]++));
        }
        return merged;
    }

    private static BytesRef keyword(String value, int ignoreAbove) {
        // values longer than ignore_above are not indexed in the keyword field, so they sort as missing
        return value == null || value.length() > ignoreAbove ? null : new BytesRef(value);
    }

    private static Instant parseEpochMillis(String value) {
        try {
            return Instant.ofEpochMilli(Long.parseLong(value));
        } catch (NumberFormatException e) {
            // cannot interpret the custom missing value, sort missing values last
            return null;
        }
    }
}
