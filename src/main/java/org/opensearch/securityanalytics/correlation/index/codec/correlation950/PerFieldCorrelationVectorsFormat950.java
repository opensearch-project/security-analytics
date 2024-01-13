/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec.correlation950;

import org.apache.lucene.backward_codecs.lucene95.Lucene95HnswVectorsFormat;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.correlation.index.codec.BasePerFieldCorrelationVectorsFormat;

import java.util.Optional;

public class PerFieldCorrelationVectorsFormat950 extends BasePerFieldCorrelationVectorsFormat {

    public PerFieldCorrelationVectorsFormat950(final Optional<MapperService> mapperService) {
        super(
                mapperService,
                Lucene95HnswVectorsFormat.DEFAULT_MAX_CONN,
                Lucene95HnswVectorsFormat.DEFAULT_BEAM_WIDTH,
                () -> new Lucene95HnswVectorsFormat(),
                (maxConn, beamWidth) -> new Lucene95HnswVectorsFormat(maxConn, beamWidth)
        );
    }
}