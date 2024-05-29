/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;

import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.INDEX_TIF_SOURCE_CONFIG_ACTION_NAME;

/**
 * Threat intel tif job creation action
 */
public class SAIndexTIFSourceConfigAction extends ActionType<SAIndexTIFSourceConfigResponse> {

    public static final SAIndexTIFSourceConfigAction INSTANCE = new SAIndexTIFSourceConfigAction();
    public static final String NAME = INDEX_TIF_SOURCE_CONFIG_ACTION_NAME;
    private SAIndexTIFSourceConfigAction() {
        super(NAME, SAIndexTIFSourceConfigResponse::new);
    }
}
