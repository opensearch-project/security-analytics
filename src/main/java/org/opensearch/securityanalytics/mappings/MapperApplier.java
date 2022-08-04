package org.opensearch.securityanalytics.mappings;

import org.opensearch.client.Client;

import java.util.HashMap;
import java.util.Map;

public class MapperApplier {

    private final Client client;

    private final Map<String, String> logCategoryToMappingFiles;

    public MapperApplier(Client client) {
        this.client = client;

        this.logCategoryToMappingFiles = new HashMap<>();
        this.logCategoryToMappingFiles.put("netflow", "OSMapping/NetflowMapping.json");
    }

    public void createMappingAction(String srcIndex, String logCategory) {
        getClass().getResource(this.logCategoryToMappingFiles.get(logCategory))
        // read the mapping file from resources directory
        // then prepare alias payload
        // then use the client to fire alias query
        client.admin().indices().aliases()

    }

    public void updateMappingAction(String srcIndex, String logCategory, String field) {

    }

    public void getMappingAction(String srcIndex, String logCategory) {

    }

    public void deleteMappingAction(String srcIndex, String logCategory) {

    }
}