/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index;

import org.apache.lucene.document.Field;
import org.apache.lucene.index.IndexableFieldType;
import org.apache.lucene.util.BytesRef;
import org.opensearch.securityanalytics.correlation.index.codec.util.CorrelationVectorAsArraySerializer;
import org.opensearch.securityanalytics.correlation.index.codec.util.CorrelationVectorSerializer;

public class VectorField extends Field {

    public VectorField(String name, float[] value, IndexableFieldType type) {
        super(name, new BytesRef(), type);
        try {
            final CorrelationVectorSerializer vectorSerializer = new CorrelationVectorAsArraySerializer();
            final byte[] floatToByte = vectorSerializer.floatToByteArray(value);
            this.setBytesValue(floatToByte);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}