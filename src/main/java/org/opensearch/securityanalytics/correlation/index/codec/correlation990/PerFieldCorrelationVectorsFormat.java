/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec.correlation990;

import org.apache.lucene.codecs.lucene99.Lucene99HnswVectorsFormat;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.correlation.index.codec.BasePerFieldCorrelationVectorsFormat;

import java.util.Optional;

public class PerFieldCorrelationVectorsFormat extends BasePerFieldCorrelationVectorsFormat {

    public PerFieldCorrelationVectorsFormat(final Optional<MapperService> mapperService) {
        super(
                mapperService,
                Lucene99HnswVectorsFormat.DEFAULT_MAX_CONN,
                Lucene99HnswVectorsFormat.DEFAULT_BEAM_WIDTH,
                () -> new Lucene99HnswVectorsFormat(),
                (maxConn, beamWidth) -> new Lucene99HnswVectorsFormat(maxConn, beamWidth)
        );
    }
}