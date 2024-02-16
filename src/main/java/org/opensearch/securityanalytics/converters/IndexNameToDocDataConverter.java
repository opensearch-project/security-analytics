/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.converters;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.commons.alerting.model.IdDocPair;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

public class IndexNameToDocDataConverter {
    public Map<String, List<DocData>> convert(final BulkRequest bulkRequest, final BulkResponse bulkResponse) {
        if (bulkRequest.requests().size() != bulkResponse.getItems().length) {
            throw new SecurityAnalyticsException(
                    "BulkRequest item length did not match BulkResponse item length. Unable to proceed.",
                    RestStatus.INTERNAL_SERVER_ERROR,
                    null
            );
        }

        final Map<String, List<DocData>> indexToDocData = new HashMap<>();
        IntStream.range(0, bulkRequest.requests().size()).forEach(requestIndex -> {
            final DocWriteRequest<?> request = bulkRequest.requests().get(requestIndex);
            final BulkItemResponse response = bulkResponse.getItems()[requestIndex];

            // No work for SAP to do if doc is being deleted or DocWriteRequest failed
            if (isDeleteOperation(request) || response.isFailed()) {
                return;
            }

            indexToDocData.putIfAbsent(request.index(), new ArrayList<>());
            final BytesReference document = getDocument(request);
            final String docId = response.getId();
            final IdDocPair idDocPair = new IdDocPair(docId, document);
            final DocData docData = new DocData(idDocPair, requestIndex);

            indexToDocData.get(request.index()).add(docData);
        });

        return indexToDocData;
    }

    private boolean isDeleteOperation(final DocWriteRequest<?> docWriteRequest) {
        return DocWriteRequest.OpType.DELETE.equals(docWriteRequest.opType());
    }

    private BytesReference getDocument(final DocWriteRequest<?> docWriteRequest) {
        switch (docWriteRequest.opType()) {
            case CREATE:
            case INDEX: return ((IndexRequest) docWriteRequest).source();
            case UPDATE: return ((UpdateRequest) docWriteRequest).doc().source();
            default: throw new UnsupportedOperationException("No handler for operation type: " + docWriteRequest.opType());
        }
    }
}
