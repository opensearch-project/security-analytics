/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

/**
 * Threat intel datasource delete action
 */
public class DeleteDatasourceAction extends ActionType<AcknowledgedResponse> {
    /**
     * Delete datasource action instance
     */
    public static final DeleteDatasourceAction INSTANCE = new DeleteDatasourceAction();
    /**
     * Delete datasource action name
     */
    public static final String NAME = "cluster:admin/security_analytics/datasource/delete";

    private DeleteDatasourceAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
