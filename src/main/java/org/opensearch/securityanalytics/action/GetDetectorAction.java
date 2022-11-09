/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetDetectorAction extends ActionType<GetDetectorResponse> {

    public static final GetDetectorAction INSTANCE = new GetDetectorAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/detector/get";

    public GetDetectorAction() {
        super(NAME, GetDetectorResponse::new);
    }
}