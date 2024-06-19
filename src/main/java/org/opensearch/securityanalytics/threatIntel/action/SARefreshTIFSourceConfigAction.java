/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

import static org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigAction.REFRESH_TIF_SOURCE_CONFIG_ACTION_NAME;

/**
 * Refresh TIF Source Config Action
 */
public class SARefreshTIFSourceConfigAction extends ActionType<AcknowledgedResponse> {

    public static final SARefreshTIFSourceConfigAction INSTANCE = new SARefreshTIFSourceConfigAction();

    public static final String NAME = REFRESH_TIF_SOURCE_CONFIG_ACTION_NAME;
    private SARefreshTIFSourceConfigAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
