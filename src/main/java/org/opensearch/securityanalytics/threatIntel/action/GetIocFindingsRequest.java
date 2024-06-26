/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

public class GetIocFindingsRequest extends ActionRequest {

    private List<String> findingIds;

    private List<String> iocIds;

    private Instant startTime;

    private Instant endTime;

    private Table table;

    public GetIocFindingsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalStringList(),
                sin.readOptionalStringList(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant(),
                Table.readFrom(sin)
        );
    }

    public GetIocFindingsRequest(List<String> findingIds,
                                 List<String> iocIds,
                                 Instant startTime,
                                 Instant endTime,
                                 Table table) {
        this.findingIds = findingIds;
        this.iocIds = iocIds;
        this.startTime = startTime;
        this.endTime = endTime;
        this.table = table;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (startTime != null && endTime != null && startTime.isAfter(endTime)) {
            validationException = ValidateActions.addValidationError(String.format(Locale.getDefault(),
                    "startTime should be less than endTime"), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalStringCollection(findingIds);
        out.writeOptionalStringCollection(iocIds);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
        table.writeTo(out);
    }

    public List<String> getFindingIds() {
        return findingIds;
    }

    public List<String> getIocIds() {
        return iocIds;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public Table getTable() {
        return table;
    }
}