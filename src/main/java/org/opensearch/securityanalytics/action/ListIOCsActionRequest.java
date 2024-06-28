/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.securityanalytics.commons.model.IOCType;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;

public class ListIOCsActionRequest extends ActionRequest {

    public static String SEARCH_FIELD = "search";
    public static String TYPE_FIELD = "ioc_types";
    public static String ALL_TYPES_FILTER = "ALL";

    private final Table table;
    private List<String> types;
    private List<String> feedIds;

    public ListIOCsActionRequest(List<String> types, List<String> feedIds, Table table) {
        this.table = table;
        this.types = types == null
                ? emptyList()
                : types.stream().map(t -> t.toLowerCase(Locale.ROOT)).collect(Collectors.toList());
        this.feedIds = feedIds == null ? emptyList() : feedIds;
    }

    public ListIOCsActionRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalStringList(), // type
                sin.readOptionalStringList(), //feedId
                Table.readFrom(sin) //table

        );
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalStringCollection(types);
        out.writeOptionalStringCollection(feedIds);
        table.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (table.getStartIndex() < 0) {
            validationException = ValidateActions
                    .addValidationError(String.format("start_index param cannot be a negative number."), validationException);
        } else if (table.getSize() < 0 || table.getSize() > 10000) {
            validationException = ValidateActions
                    .addValidationError(String.format("size param must be between 0 and 10,000."), validationException);
        } else {
            for (String type : types) {
                if (!ALL_TYPES_FILTER.equalsIgnoreCase(type)) {
                    try {
                        IOCType.valueOf(type);
                    } catch (IllegalArgumentException e) {
                        validationException = ValidateActions
                                .addValidationError(String.format("Unrecognized [%s] param.", TYPE_FIELD), validationException);
                        break;
                    }
                }
            }
        }
        return validationException;
    }

    public Table getTable() {
        return table;
    }

    public List<String> getTypes() {
        return types;
    }

    public List<String> getFeedIds() {
        return feedIds;
    }

    public enum SortOrder {
        asc,
        dsc
    }
}
