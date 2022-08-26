/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mappings;

import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.client.Client;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class MapperApplier {

    IndicesAdminClient indicesClient;

    public MapperApplier(Client client) {
        this.indicesClient = client.admin().indices();
    }

    public void createMappingAction(String logIndex, String ruleTopic) throws IOException {
        PutMappingRequest request = new PutMappingRequest(logIndex).source(
                MapperFacade.aliasMappings(ruleTopic), XContentType.JSON
        );
        indicesClient.putMapping(request);
    }

    public void updateMappingAction(String logIndex, String field, String alias) throws IOException {
        PutMappingRequest request = new PutMappingRequest(logIndex).source(field, alias);
        indicesClient.putMapping(request);
    }

    public ImmutableOpenMap<String, MappingMetadata> readMappingAction(String logIndex) throws IOException, ExecutionException, InterruptedException {
        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices(logIndex);
        return indicesClient.getMappings(getMappingsRequest).get().getMappings();
    }
}