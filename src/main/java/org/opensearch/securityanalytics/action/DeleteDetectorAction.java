/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class DeleteDetectorAction extends ActionType<DeleteDetectorResponse> {

    public static final DeleteDetectorAction INSTANCE = new DeleteDetectorAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/detector/delete";

    public DeleteDetectorAction() {
        super(NAME, DeleteDetectorResponse::new);
    }
}