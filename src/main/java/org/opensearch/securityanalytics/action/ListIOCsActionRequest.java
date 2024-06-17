/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.securityanalytics.commons.model.IOCType;

import java.io.IOException;
import java.util.Locale;

public class ListIOCsActionRequest extends ActionRequest {
    public static String START_INDEX_FIELD = "start";
    public static String SIZE_FIELD = "size";
    public static String SORT_ORDER_FIELD = "sort_order";
    public static String SORT_STRING_FIELD = "sort_string";
    public static String SEARCH_FIELD = "search";
    public static String TYPE_FIELD = "type";
    public static String ALL_TYPES_FILTER = "ALL";

    private int startIndex;
    private int size;
    private SortOrder sortOrder;
    private String sortString;

    private String search;
    private String type;
    private String feedId;

    public ListIOCsActionRequest(int startIndex, int size, String sortOrder, String sortString, String search, String type, String feedId) {
        super();
        this.startIndex = startIndex;
        this.size = size;
        this.sortOrder = SortOrder.valueOf(sortOrder.toLowerCase(Locale.ROOT));
        this.sortString = sortString;
        this.search = search;
        this.type = type.toLowerCase(Locale.ROOT);
        this.feedId = feedId;
    }

    public ListIOCsActionRequest(StreamInput sin) throws IOException {
        this(
                sin.readInt(), // startIndex
                sin.readInt(), // size
                sin.readString(), // sortOrder
                sin.readString(), // sortString
                sin.readOptionalString(), // search
                sin.readOptionalString(), // type
                sin.readOptionalString() //feedId
        );
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeInt(startIndex);
        out.writeInt(size);
        out.writeEnum(sortOrder);
        out.writeString(sortString);
        out.writeOptionalString(search);
        out.writeOptionalString(type);
        out.writeOptionalString(feedId);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (startIndex < 0) {
            validationException = ValidateActions
                    .addValidationError(String.format("[%s] param cannot be a negative number.", START_INDEX_FIELD), validationException);
        } else if (size < 0 || size > 10000) {
            validationException = ValidateActions
                    .addValidationError(String.format("[%s] param must be between 0 and 10,000.", SIZE_FIELD), validationException);
        } else if (!ALL_TYPES_FILTER.equalsIgnoreCase(type)) {
            try {
                IOCType.valueOf(type);
            } catch (Exception e) {
                validationException = ValidateActions
                        .addValidationError(String.format("Unrecognized [%s] param.", TYPE_FIELD), validationException);
            }
        }
        return validationException;
    }

    public int getStartIndex() {
        return startIndex;
    }

    public int getSize() {
        return size;
    }

    public SortOrder getSortOrder() {
        return sortOrder;
    }

    public String getSortString() {
        return sortString;
    }

    public String getSearch() {
        return search;
    }

    public String getType() {
        return type;
    }

    public String getFeedId() {
        return feedId;
    }

    public enum SortOrder {
        asc,
        dsc
    }
}
