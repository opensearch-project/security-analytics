/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

/**
 * Threat intel tif job state
 *
 * When tif job is created, it starts with CREATING state. Once the first threat intel feed is generated, the state changes to AVAILABLE.
 * Only when the first threat intel feed generation failed, the state changes to CREATE_FAILED.
 * Subsequent threat intel feed failure won't change tif job state from AVAILABLE to CREATE_FAILED.
 * When delete request is received, the tif job state changes to DELETING.
 *
 * State changed from left to right for the entire lifecycle of a datasource
 * (CREATING) to (CREATE_FAILED or AVAILABLE) to (DELETING)
 *
 */
public enum TIFJobState {
    /**
     * tif job is being created
     */
    CREATING,
    /**
     * tif job is ready to be used
     */
    AVAILABLE,
    /**
     * tif job creation failed
     */
    CREATE_FAILED,
    /**
     * tif job is being deleted
     */
    DELETING,

    /**
     * tif associated iocs are being refreshed
     */
    REFRESHING,

    /**
     * tif refresh job failed
     */
    REFRESH_FAILED
}
