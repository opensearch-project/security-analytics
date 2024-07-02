/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class ListIOCsAction extends ActionType<ListIOCsActionResponse> {
    public static final ListIOCsAction INSTANCE = new ListIOCsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/threatintel/iocs/list";

    public ListIOCsAction() {
        super(NAME, ListIOCsActionResponse::new);
    }
}
