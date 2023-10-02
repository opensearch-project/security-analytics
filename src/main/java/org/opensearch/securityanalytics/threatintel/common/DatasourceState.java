/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.common;

/**
 * Threat intel datasource state
 *
 * When data source is created, it starts with CREATING state. Once the first threatIP data is generated, the state changes to AVAILABLE.
 * Only when the first threatIP data generation failed, the state changes to CREATE_FAILED.
 * Subsequent threatIP data failure won't change data source state from AVAILABLE to CREATE_FAILED.
 * When delete request is received, the data source state changes to DELETING.
 *
 * State changed from left to right for the entire lifecycle of a datasource
 * (CREATING) to (CREATE_FAILED or AVAILABLE) to (DELETING)
 *
 */
public enum DatasourceState {
    /**
     * Data source is being created
     */
    CREATING,
    /**
     * Data source is ready to be used
     */
    AVAILABLE,
    /**
     * Data source creation failed
     */
    CREATE_FAILED,
    /**
     * Data source is being deleted
     */
    DELETING
}
