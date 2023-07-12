/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec;

import org.apache.lucene.codecs.KnnVectorsFormat;
import org.apache.lucene.codecs.perfield.PerFieldKnnVectorsFormat;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.correlation.CorrelationConstants;
import org.opensearch.securityanalytics.correlation.index.mapper.CorrelationVectorFieldMapper;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public abstract class BasePerFieldCorrelationVectorsFormat extends PerFieldKnnVectorsFormat {

    private final Optional<MapperService> mapperService;
    private final int defaultMaxConnections;
    private final int defaultBeamWidth;
    private final Supplier<KnnVectorsFormat> defaultFormatSupplier;
    private final BiFunction<Integer, Integer, KnnVectorsFormat> formatSupplier;

    public BasePerFieldCorrelationVectorsFormat(Optional<MapperService> mapperService,
                                                int defaultMaxConnections,
                                                int defaultBeamWidth,
                                                Supplier<KnnVectorsFormat> defaultFormatSupplier,
                                                BiFunction<Integer, Integer, KnnVectorsFormat> formatSupplier) {
        this.mapperService = mapperService;
        this.defaultMaxConnections = defaultMaxConnections;
        this.defaultBeamWidth = defaultBeamWidth;
        this.defaultFormatSupplier = defaultFormatSupplier;
        this.formatSupplier = formatSupplier;
    }

    @Override
    public KnnVectorsFormat getKnnVectorsFormatForField(String field) {
        if (!isCorrelationVectorFieldType(field)) {
            return defaultFormatSupplier.get();
        }

        var type = (CorrelationVectorFieldMapper.CorrelationVectorFieldType) mapperService.orElseThrow(
                () -> new IllegalArgumentException(String.format(Locale.getDefault(),
                        "Cannot read field type for field [%s] because mapper service is not available", field)))
                .fieldType(field);

        var params = type.getCorrelationParams().getParameters();
        int maxConnections = getMaxConnections(params);
        int beamWidth = getBeamWidth(params);

        return formatSupplier.apply(maxConnections, beamWidth);
    }

    private boolean isCorrelationVectorFieldType(final String field) {
        return mapperService.isPresent() && mapperService.get().fieldType(field) instanceof CorrelationVectorFieldMapper.CorrelationVectorFieldType;
    }

    private int getMaxConnections(final Map<String, Object> params) {
        if (params != null && params.containsKey(CorrelationConstants.METHOD_PARAMETER_M)) {
            return (int) params.get(CorrelationConstants.METHOD_PARAMETER_M);
        }
        return defaultMaxConnections;
    }

    private int getBeamWidth(final Map<String, Object> params) {
        if (params != null && params.containsKey(CorrelationConstants.METHOD_PARAMETER_EF_CONSTRUCTION)) {
            return (int) params.get(CorrelationConstants.METHOD_PARAMETER_EF_CONSTRUCTION);
        }
        return defaultBeamWidth;
    }
}