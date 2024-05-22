/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

/**
 * Types of feeds threat intel can support
 * Feed types include: licensed, open-sourced, custom, and internal
 */
public enum FeedType {

    LICENSED,

    OPEN_SOURCED,

    CUSTOM,

    INTERNAL
}
