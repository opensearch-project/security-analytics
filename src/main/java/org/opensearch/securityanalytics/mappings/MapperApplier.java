/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mappings;

import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.common.xcontent.XContentType;

import java.io.IOException;

public class MapperApplier {

    public PutMappingRequest createMappingAction(String logIndex, String ruleTopic) throws IOException {
        return new PutMappingRequest(logIndex)
                .source(MapperFacade.aliasMappings(ruleTopic), XContentType.JSON);
    }

    public void updateMappingAction(String logIndex, String ruleTopic, String field, String alias) {

    }

    public void readMappingAction(String logIndex, String ruleTopic) {

    }
}