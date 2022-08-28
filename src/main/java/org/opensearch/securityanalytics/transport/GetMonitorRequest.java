/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import java.io.IOException;

class GetMonitorRequest extends ActionRequest {
    public String monitorId;
    public Long version;
    public RestRequest.Method method;
    public FetchSourceContext srcContext;//?

    void constructor(
            String monitorId,
            Long version,
            RestRequest.Method method,
            FetchSourceContext srcContext //?
    ){
        //this.super();
        this.monitorId = monitorId;
        this.version = version;
        this.method = method;
        this.srcContext = srcContext;
        return;
    }

    //@Throws(IOException::class)
//    void constructor(StreamInput sin){
//        this.monitorId = sin.readString(); // monitorId
//        this.version = sin.readLong(); // version
//        this.method = sin.readEnum(RestRequest.Method::class.java); // method
//        if (sin.readBoolean()) {
//            return FetchSourceContext(sin); // srcContext
//        } else return null;
//    }

    //@override
    public ActionRequestValidationException validate() { //?
        return null;
    }

    //@throws(IOException::class)
    //@override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(monitorId);
        out.writeLong(version);
        out.writeEnum(method);
        out.writeBoolean(srcContext != null);
        srcContext.writeTo(out); //?
    }
}
