/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;

import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.DELETE_TIF_SOURCE_CONFIG_ACTION_NAME;

/**
 * Delete TIF Source Config Action
 */
public class SADeleteTIFSourceConfigAction extends ActionType<SADeleteTIFSourceConfigResponse> {

    public static final SADeleteTIFSourceConfigAction INSTANCE = new SADeleteTIFSourceConfigAction();
    public static final String NAME = DELETE_TIF_SOURCE_CONFIG_ACTION_NAME;
    private SADeleteTIFSourceConfigAction() {
        super(NAME, SADeleteTIFSourceConfigResponse::new);
    }
}
