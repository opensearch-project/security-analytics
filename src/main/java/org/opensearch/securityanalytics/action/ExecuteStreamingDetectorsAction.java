/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.bulk.BulkResponse;

public class ExecuteStreamingDetectorsAction extends ActionType<BulkResponse> {
    public static final ExecuteStreamingDetectorsAction INSTANCE = new ExecuteStreamingDetectorsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/detectors/streaming/execute";

    public ExecuteStreamingDetectorsAction() {
        super(NAME, BulkResponse::new);
    }
}
