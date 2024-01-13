/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec;

import org.apache.lucene.codecs.Codec;
import org.apache.lucene.codecs.lucene99.Lucene99Codec;
import org.apache.lucene.backward_codecs.lucene95.Lucene95Codec;
import org.apache.lucene.codecs.perfield.PerFieldKnnVectorsFormat;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.correlation.index.codec.correlation950.CorrelationCodec950;
import org.opensearch.securityanalytics.correlation.index.codec.correlation990.CorrelationCodec990;
import org.opensearch.securityanalytics.correlation.index.codec.correlation990.PerFieldCorrelationVectorsFormat990;
import org.opensearch.securityanalytics.correlation.index.codec.correlation950.PerFieldCorrelationVectorsFormat950;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public enum CorrelationCodecVersion {
    V_9_5_0(
            "CorrelationCodec950",
            new Lucene95Codec(),
            new PerFieldCorrelationVectorsFormat950(Optional.empty()),
            (userCodec, mapperService) -> new CorrelationCodec950(userCodec, new PerFieldCorrelationVectorsFormat950(Optional.of(mapperService))),
            CorrelationCodec950::new
    ),
    V_9_9_0(
            "CorrelationCodec990",
            new Lucene99Codec(),
            new PerFieldCorrelationVectorsFormat990(Optional.empty()),
            (userCodec, mapperService) -> new CorrelationCodec990(userCodec, new PerFieldCorrelationVectorsFormat990(Optional.of(mapperService))),
            CorrelationCodec990::new
    );

    private static final CorrelationCodecVersion CURRENT = V_9_9_0;
    private final String codecName;
    private final Codec defaultCodecDelegate;
    private final PerFieldKnnVectorsFormat perFieldKnnVectorsFormat;
    private final BiFunction<Codec, MapperService, Codec> correlationCodecSupplier;
    private final Supplier<Codec> defaultCorrelationCodecSupplier;

    CorrelationCodecVersion(String codecName,
                            Codec defaultCodecDelegate,
                            PerFieldKnnVectorsFormat perFieldKnnVectorsFormat,
                            BiFunction<Codec, MapperService, Codec> correlationCodecSupplier,
                            Supplier<Codec> defaultCorrelationCodecSupplier) {
        this.codecName = codecName;
        this.defaultCodecDelegate = defaultCodecDelegate;
        this.perFieldKnnVectorsFormat = perFieldKnnVectorsFormat;
        this.correlationCodecSupplier = correlationCodecSupplier;
        this.defaultCorrelationCodecSupplier = defaultCorrelationCodecSupplier;
    }

    public String getCodecName() {
        return codecName;
    }

    public Codec getDefaultCodecDelegate() {
        return defaultCodecDelegate;
    }

    public PerFieldKnnVectorsFormat getPerFieldCorrelationVectorsFormat() {
        return perFieldKnnVectorsFormat;
    }

    public BiFunction<Codec, MapperService, Codec> getCorrelationCodecSupplier() {
        return correlationCodecSupplier;
    }

    public Supplier<Codec> getDefaultCorrelationCodecSupplier() {
        return defaultCorrelationCodecSupplier;
    }

    public static final CorrelationCodecVersion current() {
        return CURRENT;
    }
}