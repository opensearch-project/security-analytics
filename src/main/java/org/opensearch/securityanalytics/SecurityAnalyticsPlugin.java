/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.opensearch.plugins.Plugin;
import org.apache.http.HttpHost; import org.apache.http.auth.AuthScope; 
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider; 
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.base.RestClientTransport;
import org.opensearch.client.base.Transport; 
import org.opensearch.client.json.jackson.JacksonJsonpMapper; 
import org.opensearch.client.opensearch.OpenSearchClient; 
import org.opensearch.client.opensearch._global.IndexRequest; 
import org.opensearch.client.opensearch._global.IndexResponse; 
import org.opensearch.client.opensearch._global.SearchResponse; 
import org.opensearch.client.opensearch.indices.*; 
import org.opensearch.client.opensearch.indices.put_settings.IndexSettingsBody; 

import java.io.IOException; 

public class SecurityAnalyticsPlugin extends Plugin {
    public static void main(String[] args) {
     RestClient restClient = null; 

try{
 System.setProperty("javax.net.ssl.trustStore", "/full/path/to/keystore");
System.setProperty("javax.net.ssl.trustStorePassword", "password-to-keystore"); 

//Only for demo purposes.  
final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials("admin", "admin")); 

//Initialize the client with SSL and TLS enabled 
restClient = RestClient.builder(new HttpHost("localhost", 9200, "https")). setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() { @Override public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) { 
return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider); 
}
}).build(); 

Transport transport = new RestClientTransport(restClient, new JacksonJsonpMapper());
 OpenSearchClient client = new OpenSearchClient(transport);

  //Create the index 
 String index = "sample-index"; 
 CreateRequest createIndexRequest = new CreateRequest.Builder().index(index).build();
 client.indices().create(createIndexRequest); 

 //Add some settings to the index 
IndexSettings indexSettings = new IndexSettings.Builder().autoExpandReplicas("0-all").build();
IndexSettingsBody settingsBody = new IndexSettingsBody.Builder().settings(indexSettings).build();
PutSettingsRequest putSettingsRequest = new PutSettingsRequest.Builder().index(index).value(settingsBody).build();
client.indices().putSettings(putSettingsRequest);

 //Index some data 
IndexData indexData = new IndexData("first_name", "Bruce");
IndexRequest<IndexData> indexRequest = new IndexRequest.Builder<IndexData>().index(index).id("1").value(indexData).build();
 client.index(indexRequest); 

 //Search for the document 
 SearchResponse<IndexData> searchResponse = client.search(s -> s.index(index), IndexData.class); 
 for (int i = 0; i< searchResponse.hits().hits().size(); i++) {


  System.out.println(searchResponse.hits().hits().get(i).source());
   } 
// Delete the document
client.delete(b -> b.index(index).id("1"));
// Delete the index
DeleteRequest deleteRequest = new DeleteRequest.Builder().index(index).build();
DeleteResponse deleteResponse = client.indices().delete(deleteRequest);




 //  Indices Aliases Request ->The index aliases API allows aliasing an index with  a name ,
   //with all APIs automatically converting  the aliase name to the actual index name

//Implementing sigma rules for each data type
Data d= new Data(true,"firstData",1,1.0);
boolean getBoolData = d.getBoolData();

SigmaTypeFacade sigmaTypeFacadeB = new SigmaTypeFacade(getBoolData );
SigmaBool sigmaBool = new SigmaBool(getBoolData);

SigmaTypeFacade sigmaTypeFacadeS = new SigmaTypeFacade(d.getMessage());
SigmaString sigmaString = new SigmaString(d.getMessage());

SigmaTypeFacade sigmaTypeFacadeN = new SigmaTypeFacade(d.getIntData());
SigmaNumber sigmaNumber = new SigmaNumber(d.getIntData());

SigmaTypeFacade sigmaTypeFacadell = new SigmaTypeFacade();
SigmaNull sigmaNull= new SigmaNull();


if(sigmaTypeFacadeB == true && sigmaTypeFacadeS = true && sigmaTypeFacadeN == true  && sigmaTypeFacadell ==true ){

//create update to opensearch for a particular uniquid with POJO
    IndexRequest request = new IndexRequest("DataIndex");
    request.id("001");

    request.source(new(ObjectMapper().writeValueAsString(d),XcontentType.JSON);
    IndexResponse IndexResponse = client.index(request,RequestOptions.DEFAULT);
        System.out.println("response id : " + indexResponse.getId());
        System.out.println(indexResponse.getResult().Message);
//changing the index to sigma rule name
    IndicesAliasesRequest request = new IndicesAliasesRequest(); 
    AliasActions aliasAction =
            new AliasActions(AliasActions.Type.ADD)
            .index("DataIndex")
            .alias("sigmaAliasApproved"); 
        request.addAliasAction(aliasAction); 


        AliasActions addIndexAction =
        new AliasActions(AliasActions.Type.ADD)
        .index("DataIndex")
        .alias("SigmaString")
        .filter("{\"term\":{\"Message\":This is sigma approved message}}");

           AliasActions addIndexAction =
        new AliasActions(AliasActions.Type.ADD)
        .index("DataIndex")
        .alias("SigmaNumber")
        .filter("{\"term\":{\"Number\":1}}");


           AliasActions addIndexAction =
        new AliasActions(AliasActions.Type.ADD)
        .index("DataIndex")
        .alias("SigmaFloat")
        .filter("{\"term\":{\"Float\":1.0}}");
           AliasActions addIndexAction =
        new AliasActions(AliasActions.Type.ADD)
        .index("DataIndex")
        .alias("SigmaBool")
        .filter("{\"term\":{\"bool\":true}}");
/*

AliasActions addIndicesAction =
        new AliasActions(AliasActions.Type.ADD)
        .indices("index1", "index2")
        .alias("alias2")
        .routing("1"); 
AliasActions removeAction =
        new AliasActions(AliasActions.Type.REMOVE)
        .index("index3")
        .alias("alias3"); 
AliasActions removeIndexAction =
        new AliasActions(AliasActions.Type.REMOVE_INDEX)
        .index("index4"); 
    */
    }
            request.timeout(TimeValue.timeValueMinutes(2)); 
request.timeout("2m"); 
request.masterNodeTimeout(TimeValue.timeValueMinutes(1)); 
request.masterNodeTimeout("1m"); 
/*
When executing a IndicesAliasesRequest in the following manner, 
the client waits for the IndicesAliasesResponse to be returned before continuing with code execution:
*/
AcknowledgedResponse indicesAliasesResponse =
        client.indices().updateAliases(request, RequestOptions.DEFAULT);
        boolean acknowledged = indicesAliasesResponse.isAcknowledged(); 
        /*
        The returned IndicesAliasesResponse allows to retrieve information about the executed operation as follows:
        */

} catch (IOException e)
    { 
    System.out.println(e.toString()); 
} finally {
 try { 
    if (restClient != null)
     { 
        restClient.close();
    } 
        } catch (IOException e) { 
            
            System.out.println(e.toString()); 
         } 
    }

   }

}
   
 





    




