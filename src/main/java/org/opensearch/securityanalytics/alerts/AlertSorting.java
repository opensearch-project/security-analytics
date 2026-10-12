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
import java.util.Map;
import java.util.function.Function;
import org.apache.lucene.util.BytesRef;
import org.opensearch.commons.alerting.model.Alert;

/**
 * Merges alert pages that were fetched (and sorted by OpenSearch) from several alert indices into a single sorted page.
 * <p>
 * The comparator mirrors OpenSearch's field sort semantics for the sortable alert fields
 * ({@link org.opensearch.securityanalytics.action.GetAlertsRequest#SORTABLE_FIELDS}), as mapped by Alerting's alert
 * mapping: start_time (a date) compares chronologically (as epoch millis), the state and severity keywords and the
 * monitor_name.keyword sub-field by their UTF-8 bytes, where monitor_name.keyword ignores values longer than its
 * {@code ignore_above}, and missing values are placed according to the {@code missing} parameter ({@code _last} by
 * default, for both sort orders).
 * <p>
 * Alerting sorts each search on the requested field only, without a tie-breaker. To merge deterministically, alerts
 * that tie on the requested field are ordered by start_time descending (most recent first, compared as epoch millis,
 * an alert without start time last) and then by alert id ascending. Ties inside the alerts returned by a single
 * Alerting search keep Alerting's order, since the merge only ever compares the heads of the lists.
 */
public final class AlertSorting {

    /** ignore_above of the monitor_name.keyword sub-field in Alerting's alert mapping */
    static final int KEYWORD_IGNORE_ABOVE = 256;

    private static final String MISSING_FIRST = "_first";
    private static final String MISSING_LAST = "_last";

    /** How the value of a sortable field is read from an alert and how a custom missing value is parsed. */
    private static final class SortField {
        final Function<Alert, Comparable<?>> value;
        final Function<String, Comparable<?>> parseMissing;

        SortField(Function<Alert, Comparable<?>> value, Function<String, Comparable<?>> parseMissing) {
            this.value = value;
            this.parseMissing = parseMissing;
        }
    }

    private static final Map<String, SortField> SORT_FIELDS = Map.of(
            "start_time", date(Alert::getStartTime),
            "monitor_name.keyword", keyword(Alert::getMonitorName, KEYWORD_IGNORE_ABOVE),
            "state", keyword(alert -> alert.getState().name(), Integer.MAX_VALUE),
            "severity", keyword(Alert::getSeverity, Integer.MAX_VALUE)
    );

    /**
     * Orders alerts that tie on the requested sort field: start_time descending, then alert id ascending. The alert id
     * is unique, so this makes the merge order independent of the order of the merged lists.
     */
    static final Comparator<Alert> TIE_BREAKER = Comparator
            .comparing((Alert alert) -> alert.getStartTime() == null ? null : alert.getStartTime().toEpochMilli(),
                    Comparator.nullsLast(Comparator.<Long>reverseOrder()))
            .thenComparing(Alert::getId, Comparator.nullsLast(Comparator.<String>naturalOrder()));

    private AlertSorting() {
    }

    /** Whether alert pages can be merged on the field, i.e. whether {@link #comparator} supports it. */
    public static boolean isSupported(String sortString) {
        return sortString != null && SORT_FIELDS.containsKey(sortString);
    }

    /**
     * The merge order: the requested sort field (see {@link #fieldComparator}), then {@link #TIE_BREAKER}.
     *
     * @param sortString one of {@link org.opensearch.securityanalytics.action.GetAlertsRequest#SORTABLE_FIELDS}
     * @param sortOrder  asc or desc (case-insensitive)
     * @param missing    the Table's missing parameter: null/blank or _last, _first, or a custom value
     */
    public static Comparator<Alert> comparator(String sortString, String sortOrder, String missing) {
        return fieldComparator(sortString, sortOrder, missing).thenComparing(TIE_BREAKER);
    }

    /**
     * The order of OpenSearch's field sort on the requested field alone, as used by Alerting: alerts with the same
     * sort value compare equal.
     *
     * @see #comparator
     */
    static Comparator<Alert> fieldComparator(String sortString, String sortOrder, String missing) {
        SortField sortField = sortString == null ? null : SORT_FIELDS.get(sortString);
        if (sortField == null) {
            throw new IllegalArgumentException(String.format(Locale.ROOT, "sorting alerts on [%s] is not supported", sortString));
        }
        boolean descending = "desc".equalsIgnoreCase(sortOrder);
        boolean missingFirst = MISSING_FIRST.equals(missing);
        Comparable<?> missingValue = missing == null || missing.isBlank() || MISSING_FIRST.equals(missing) || MISSING_LAST.equals(missing)
                ? null
                : sortField.parseMissing.apply(missing);

        return (a, b) -> {
            Comparable<?> va = sortField.value.apply(a);
            Comparable<?> vb = sortField.value.apply(b);
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
            int result = compare(va, vb);
            return descending ? -result : result;
        };
    }

    /**
     * Merges lists that are each sorted according to {@code comparator}, keeping the relative order of every list.
     * Remaining ties between lists (none with {@link #comparator}, whose tie-breaker ends on the unique alert id) are
     * broken by list position, which keeps the merged order deterministic across pages.
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

    @SuppressWarnings("unchecked")
    private static int compare(Comparable<?> a, Comparable<?> b) {
        return ((Comparable<Object>) a).compareTo(b);
    }

    private static SortField date(Function<Alert, Instant> getter) {
        return new SortField(alert -> getter.apply(alert).toEpochMilli(), AlertSorting::parseLong);
    }

    private static SortField keyword(Function<Alert, String> getter, int ignoreAbove) {
        return new SortField(alert -> {
            String value = getter.apply(alert);
            // values longer than ignore_above are not indexed in the keyword field, so they sort as missing
            return value == null || value.length() > ignoreAbove ? null : new BytesRef(value);
        }, BytesRef::new);
    }

    /** Like OpenSearch, a custom missing value of a date field is a number (epoch millis) */
    private static Long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            // cannot interpret the custom missing value (the search of each log type fails on it too), sort missing values last
            return null;
        }
    }
}
