/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec.correlation9120;

import org.apache.lucene.codecs.Codec;
import org.apache.lucene.codecs.FilterCodec;
import org.apache.lucene.codecs.KnnVectorsFormat;
import org.apache.lucene.codecs.perfield.PerFieldKnnVectorsFormat;
import org.opensearch.securityanalytics.correlation.index.codec.CorrelationCodecVersion;

public class CorrelationCodec9120 extends FilterCodec {
    private static final CorrelationCodecVersion VERSION = CorrelationCodecVersion.V_9_12_0;
    private final PerFieldKnnVectorsFormat perFieldCorrelationVectorsFormat;

    public CorrelationCodec9120() {
        this(VERSION.getDefaultCodecDelegate(), VERSION.getPerFieldCorrelationVectorsFormat());
    }

    public CorrelationCodec9120(Codec delegate, PerFieldKnnVectorsFormat perFieldCorrelationVectorsFormat) {
        super(VERSION.getCodecName(), delegate);
        this.perFieldCorrelationVectorsFormat = perFieldCorrelationVectorsFormat;
    }

    @Override
    public KnnVectorsFormat knnVectorsFormat() {
        return perFieldCorrelationVectorsFormat;
    }
}