/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Table;

/**
 * The opaque cursor of a page of alerts in cursor paging (see
 * {@link org.opensearch.securityanalytics.action.GetAlertsPageRequest}): the sort values of an alert, as returned by
 * the search of the alerts, used as the search_after of the search of the next or previous page.
 * <p>
 * A cursor is the base64url encoding (without padding) of a small JSON object:
 * {@code {"v":1,"f":"<sortString>","o":"<asc|desc>","m":<missing or null>,"k":[<sort values>]}}. The sort field, order
 * and missing value are those of the request that returned the cursor: a cursor is only accepted by requests with the
 * same sort, since its sort values only position the page within that sort. The sort values are checked against the
 * sort (number and types of the values).
 * <p>
 * A cursor only positions the page: all the filters of the request (the monitors of the visible detectors, the
 * severity, state, time range and search string filters) always apply, so a tampered cursor cannot return alerts the
 * request would not return otherwise.
 */
public final class AlertsCursor {

    /** Version of the cursor format */
    static final int VERSION = 1;

    /** Maximum length of an encoded cursor */
    public static final int MAX_LENGTH = 2048;

    private static final Pattern BASE64URL = Pattern.compile("^[A-Za-z0-9_-]+$");

    private static final String VERSION_FIELD = "v";
    private static final String SORT_FIELD = "f";
    private static final String ORDER_FIELD = "o";
    private static final String MISSING_FIELD = "m";
    private static final String SORT_VALUES_FIELD = "k";

    private final String sortString;
    private final String sortOrder;
    private final String missing;
    private final List<Object> sortValues;

    AlertsCursor(String sortString, String sortOrder, String missing, List<Object> sortValues) {
        this.sortString = sortString;
        this.sortOrder = sortOrder.toLowerCase(Locale.ROOT);
        this.missing = normalizeMissing(missing);
        this.sortValues = Collections.unmodifiableList(new ArrayList<>(sortValues));
    }

    /** The cursor of an alert with the given sort values, in the sort of the table. */
    public static String encode(Table table, Object[] sortValues) {
        return new AlertsCursor(table.getSortString(), table.getSortOrder(), table.getMissing(), Arrays.asList(sortValues)).encode();
    }

    String encode() {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject()
                    .field(VERSION_FIELD, VERSION)
                    .field(SORT_FIELD, sortString)
                    .field(ORDER_FIELD, sortOrder)
                    .field(MISSING_FIELD, missing)
                    .startArray(SORT_VALUES_FIELD);
            for (Object value : sortValues) {
                builder.value(value);
            }
            builder.endArray().endObject();
            byte[] json = BytesReference.toBytes(BytesReference.bytes(builder));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (IOException e) {
            throw new IllegalStateException("failed to encode the alerts cursor", e);
        }
    }

    /**
     * Decodes a cursor and checks that it is a cursor of the sort of the table: same sort field, order and missing
     * value, and sort values of the types of the sort.
     *
     * @return the cursor
     * @throws IllegalArgumentException if the cursor is invalid, with the reason as message
     */
    public static AlertsCursor decode(String cursor, Table table) {
        AlertsCursor decoded = decode(cursor);
        if (Objects.equals(decoded.sortString, table.getSortString()) == false
                || decoded.sortOrder.equals(table.getSortOrder().toLowerCase(Locale.ROOT)) == false
                || Objects.equals(decoded.missing, normalizeMissing(table.getMissing())) == false) {
            throw new IllegalArgumentException(String.format(Locale.ROOT,
                    "searchAfter is a cursor of the sort [sortString=%s, sortOrder=%s, missing=%s], not of the requested sort " +
                            "[sortString=%s, sortOrder=%s, missing=%s]", decoded.sortString, decoded.sortOrder, decoded.missing,
                    table.getSortString(), table.getSortOrder(), normalizeMissing(table.getMissing())));
        }
        List<SortValueType> types = sortValueTypes(table.getSortString());
        if (decoded.sortValues.size() != types.size()) {
            throw new IllegalArgumentException(String.format(Locale.ROOT,
                    "searchAfter has %d sort values, expected %d", decoded.sortValues.size(), types.size()));
        }
        for (int i = 0; i < types.size(); i++) {
            if (types.get(i).accepts(decoded.sortValues.get(i)) == false) {
                throw new IllegalArgumentException(String.format(Locale.ROOT,
                        "searchAfter has an invalid sort value at position %d, expected %s", i, types.get(i).description));
            }
        }
        return decoded;
    }

    private static AlertsCursor decode(String cursor) {
        if (cursor == null || cursor.isEmpty()) {
            throw new IllegalArgumentException("searchAfter must not be empty");
        }
        if (cursor.length() > MAX_LENGTH || BASE64URL.matcher(cursor).matches() == false) {
            throw new IllegalArgumentException("searchAfter is not a valid cursor");
        }
        Map<String, Object> map;
        try {
            byte[] json = Base64.getUrlDecoder().decode(cursor);
            try (XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, new String(json, StandardCharsets.UTF_8))) {
                if (parser.nextToken() != XContentParser.Token.START_OBJECT) {
                    throw new IllegalArgumentException("searchAfter is not a valid cursor");
                }
                map = parser.map();
            }
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException("searchAfter is not a valid cursor");
        }
        if (Objects.equals(map.get(VERSION_FIELD), VERSION) == false) {
            throw new IllegalArgumentException("searchAfter is not a valid cursor: unsupported version");
        }
        Object sortString = map.get(SORT_FIELD);
        Object sortOrder = map.get(ORDER_FIELD);
        Object missing = map.get(MISSING_FIELD);
        Object sortValues = map.get(SORT_VALUES_FIELD);
        if (sortString instanceof String == false || sortOrder instanceof String == false
                || (missing != null && missing instanceof String == false) || sortValues instanceof List == false
                || map.size() != 5) {
            throw new IllegalArgumentException("searchAfter is not a valid cursor");
        }
        List<Object> values = new ArrayList<>();
        for (Object value : (List<?>) sortValues) {
            // JSON integers are parsed as int or long
            values.add(value instanceof Integer ? Long.valueOf((Integer) value) : value);
        }
        return new AlertsCursor((String) sortString, (String) sortOrder, (String) missing, values);
    }

    /** The search_after values: the alert's sort values */
    public Object[] getSortValues() {
        return sortValues.toArray();
    }

    String getSortString() {
        return sortString;
    }

    String getSortOrder() {
        return sortOrder;
    }

    String getMissing() {
        return missing;
    }

    private static String normalizeMissing(String missing) {
        return missing == null || missing.isBlank() ? null : missing;
    }

    /** The types of the sort values of the sorts of {@link AlertsService#sortBuilders(Table)}, in order */
    static List<SortValueType> sortValueTypes(String sortString) {
        List<SortValueType> types = new ArrayList<>();
        types.add(Alert.START_TIME_FIELD.equals(sortString) ? SortValueType.NUMBER : SortValueType.STRING_OR_NULL);
        if (Alert.START_TIME_FIELD.equals(sortString) == false) {
            types.add(SortValueType.NUMBER);
        }
        // _index
        types.add(SortValueType.STRING);
        // monitor_id
        types.add(SortValueType.STRING_OR_NULL);
        // _seq_no
        types.add(SortValueType.NUMBER);
        return types;
    }

    enum SortValueType {
        /** a date (epoch millis) or a long, never missing: OpenSearch returns Long.MIN/MAX_VALUE for missing values */
        NUMBER("a number") {
            @Override
            boolean accepts(Object value) {
                return value instanceof Long;
            }
        },
        STRING("a string") {
            @Override
            boolean accepts(Object value) {
                return value instanceof String;
            }
        },
        /** a keyword, null for a missing value */
        STRING_OR_NULL("a string or null") {
            @Override
            boolean accepts(Object value) {
                return value == null || value instanceof String;
            }
        };

        final String description;

        SortValueType(String description) {
            this.description = description;
        }

        abstract boolean accepts(Object value);
    }
}
