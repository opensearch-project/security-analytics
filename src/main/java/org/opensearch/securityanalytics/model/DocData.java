package org.opensearch.securityanalytics.model;

import org.opensearch.commons.alerting.model.IdDocPair;

public class DocData {
    private final IdDocPair idDocPair;
    private final int bulkItemResponseIndex;

    public DocData(final IdDocPair idDocPair, final int bulkItemResponseIndex) {
        this.idDocPair = idDocPair;
        this.bulkItemResponseIndex = bulkItemResponseIndex;
    }

    public IdDocPair getIdDocPair() {
        return idDocPair;
    }

    public int getBulkItemResponseIndex() {
        return bulkItemResponseIndex;
    }
}
