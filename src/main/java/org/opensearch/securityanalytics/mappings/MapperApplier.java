package org.opensearch.securityanalytics.mappings;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.client.Client;
import java.io.IOException;

public class MapperApplier {

    private final Client client;

    public MapperApplier(Client client) {
        this.client = client;
    }

    public static PutMappingRequest createMappingAction(String logIndex, String ruleTopic) throws IOException {
        return new PutMappingRequest(logIndex).source(MapperFacade.aliasMappings(ruleTopic), XContentType.JSON);
    }

    public void updateMappingAction(String logIndex, String ruleTopic) throws IOException {
        PutMappingRequest request = createMappingAction(logIndex, ruleTopic);
        client.admin().indices().putMapping(request);
    }

    public void readMappingAction(String logIndex, String ruleTopic) throws IOException {
        GetMappingsRequest request = new GetMappingsRequest();
        request.indices(logIndex);
        GetMappingsResponse getMappingResponse = (GetMappingsResponse) client.admin().indices().getMappings(request);
        getMappingResponse.getMappings().get(logIndex);
    }

    public void deleteMappingAction(String logIndex, String ruleTopic) {
        DeleteRequest request = new DeleteRequest(logIndex,ruleTopic);//the logcategory to be deleted
    }
}