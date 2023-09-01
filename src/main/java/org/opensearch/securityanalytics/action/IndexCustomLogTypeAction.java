/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class IndexCustomLogTypeAction extends ActionType<IndexCustomLogTypeResponse> {

    public static final IndexCustomLogTypeAction INSTANCE = new IndexCustomLogTypeAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/logtype/write";

    public IndexCustomLogTypeAction() {
        super(NAME, IndexCustomLogTypeResponse::new);
    }
}