package org.opensearch.securityanalytics.mappings;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentFactory.jsonBuilder;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.GetFieldMappingRequest;

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
        String file = getClass().getResource(this.logCategoryToMappingFiles.get(logCategory));

        CreateIndexRequest request = new CreateIndexRequest(srcIndex);//read the mapping file from resources directory
        // then prepare alias payload
        this.logCategoryToMappingFiles = new HashMap<>();
        logCategoryToMappingFiles.put(request, file);

        // then use the client to fire alias query
        client.admin().indices().aliases();

    }


    public void updateMappingAction(String srcIndex, String logCategory, String field,String value) {

        XContentBuilder builder = XContentFactory.jsonBuilder();
        //  Partial document source provided as XContentBuilder  object ,the elasticsearch built-in helpers to generate the JSON content
        builder.startObject();
        {
            builder.field(field);
        }
        builder.endObject();
        updateRequest request = new  UpdateRequest(srcIndex,logCategory).doc(builder);
        //updates partial document by merging exisitng document.


    }

    public void getMappingAction(String srcIndex, String logCategory) {

        GetFieldMappingRequest request = new GetFieldMappingRequest();//an empty request
        request.indices(srcIndex);//setting the indicies to fetch mapping for that is srcIndex
        request.fields(logCategory);//the filed to be returned
    }

    public void deleteMappingAction(String srcIndex, String logCategory) {
        DeleteRequest request = new DeleteRequest(srcIndex,logCategory);//the logcategory to be deleted
    }
}