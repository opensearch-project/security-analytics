/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class IndexDetectorAction extends ActionType<IndexDetectorResponse> {

    public static final IndexDetectorAction INSTANCE = new IndexDetectorAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/detector/write";

    public IndexDetectorAction() {
        super(NAME, IndexDetectorResponse::new);
    }
}