/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

/**
 * Types of feeds threat intel can support
 */
public enum SourceConfigType {
    S3_CUSTOM,
    IOC_UPLOAD,
    CUSTOM_SCHEMA_IOC_UPLOAD,
    URL_DOWNLOAD
}
