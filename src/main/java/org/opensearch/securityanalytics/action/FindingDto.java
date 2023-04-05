/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.FindingDocument;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class FindingDto implements ToXContentObject, Writeable {

    private static final String DETECTOR_ID_FIELD = "detectorId";
    private static final String FINDING_ID_FIELD = "id";
    private static final String RELATED_DOC_IDS_FIELD = "related_doc_ids";
    private static final String INDEX_FIELD = "index";
    private static final String QUERIES_FIELD = "queries";
    private static final String TIMESTAMP_FIELD = "timestamp";
    private static final String DOCUMENTS_LIST = "document_list";

    private String id;
    private List<String> relatedDocIds;
    private String index;
    private List<DocLevelQuery> docLevelQueries;
    private Instant timestamp;
    private List<FindingDocument> documents;

    private String detectorId;

    public FindingDto(
            String detectorId,
            String id,
            List<String> relatedDocIds,
            String index,
            List<DocLevelQuery> docLevelQueries,
            Instant timestamp,
            List<FindingDocument> documents
    ) {
        this.detectorId = detectorId;
        this.id = id;
        this.relatedDocIds = relatedDocIds;
        this.index = index;
        this.docLevelQueries = docLevelQueries;
        this.timestamp = timestamp;
        this.documents = documents;
    }

    public FindingDto(StreamInput sin) throws IOException {
        this(
            sin.readString(),
            sin.readString(),
            sin.readStringList(),
            sin.readString(),
            sin.readList(DocLevelQuery::readFrom),
            sin.readInstant(),
            sin.readList(FindingDocument::new)
        );
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject()
                .field(DETECTOR_ID_FIELD, detectorId)
                .field(FINDING_ID_FIELD, id)
                .field(RELATED_DOC_IDS_FIELD, relatedDocIds)
                .field(INDEX_FIELD, index)
                .field(QUERIES_FIELD, docLevelQueries)
                .field(TIMESTAMP_FIELD, timestamp.toEpochMilli())
                .field(DOCUMENTS_LIST, documents);
        builder.endObject();
        return builder;
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        out.writeString(id);
        out.writeStringCollection(relatedDocIds);
        out.writeString(index);
        out.writeCollection(docLevelQueries);
        out.writeInstant(timestamp);
        out.writeList(documents);
    }

    public String getId() {
        return id;
    }

    public List<String> getRelatedDocIds() {
        return relatedDocIds;
    }

    public String getIndex() {
        return index;
    }

    public List<DocLevelQuery> getDocLevelQueries() {
        return docLevelQueries;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public List<FindingDocument> getDocuments() {
        return documents;
    }

    public String getDetectorId() {
        return detectorId;
    }
}
