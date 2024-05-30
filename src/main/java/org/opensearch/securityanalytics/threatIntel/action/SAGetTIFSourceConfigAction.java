/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;

import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.GET_TIF_SOURCE_CONFIG_ACTION_NAME;

/**
 * Get TIF Source Config Action
 */
public class SAGetTIFSourceConfigAction extends ActionType<SAGetTIFSourceConfigResponse> {

    public static final SAGetTIFSourceConfigAction INSTANCE = new SAGetTIFSourceConfigAction();
    public static final String NAME = GET_TIF_SOURCE_CONFIG_ACTION_NAME;
    private SAGetTIFSourceConfigAction() {
        super(NAME, SAGetTIFSourceConfigResponse::new);
    }
}
