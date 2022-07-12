package org.opensearch.securityanalytics;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.plugins.Plugin;

public class Indices{
    IndicesAliasesRequest request = new IndicesAliasesRequest();
    IndicesAliasesRequest.AliasActions aliasAction =
            new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                    .index("index1")
                    .alias("alias1");
request.addAliasAction(aliasAction);
    IndicesAliasesRequest.AliasActions addIndexAction =
            new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                    .index("index1")
                    .alias("alias1")
                    .filter("{\"term\":{\"year\":2016}}");
    IndicesAliasesRequest.AliasActions addIndicesAction =
            new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.ADD)
                    .indices("index1", "index2")
                    .alias("alias2")
                    .routing("1");
    IndicesAliasesRequest.AliasActions removeAction =
            new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.REMOVE)
                    .index("index3")
                    .alias("alias3");
    IndicesAliasesRequest.AliasActions removeIndexAction =
            new IndicesAliasesRequest.AliasActions(IndicesAliasesRequest.AliasActions.Type.REMOVE_INDEX)
                    .index("index4");
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
}
