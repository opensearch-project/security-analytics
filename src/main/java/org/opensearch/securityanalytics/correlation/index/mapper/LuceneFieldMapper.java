/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.mapper;

import org.apache.lucene.document.FieldType;
import org.apache.lucene.document.KnnVectorField;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.index.DocValuesType;
import org.apache.lucene.index.VectorSimilarityFunction;
import org.opensearch.common.Explicit;
import org.opensearch.index.mapper.ParseContext;
import org.opensearch.securityanalytics.correlation.index.CorrelationParamsContext;
import org.opensearch.securityanalytics.correlation.index.VectorField;

import java.io.IOException;
import java.util.Optional;

import static org.apache.lucene.index.VectorValues.MAX_DIMENSIONS;

public class LuceneFieldMapper extends CorrelationVectorFieldMapper {

    private static final int LUCENE_MAX_DIMENSION = MAX_DIMENSIONS;

    private final FieldType vectorFieldType;

    public LuceneFieldMapper(final CreateLuceneFieldMapperInput input) {
        super(
                input.getName(),
                input.getMappedFieldType(),
                input.getMultiFields(),
                input.getCopyTo(),
                input.getIgnoreMalformed(),
                input.isStored(),
                input.isHasDocValues()
        );

        this.correlationParams = input.getCorrelationParams();
        final VectorSimilarityFunction vectorSimilarityFunction = this.correlationParams.getSimilarityFunction();

        final int dimension = input.getMappedFieldType().getDimension();
        if (dimension > LUCENE_MAX_DIMENSION) {
            throw new IllegalArgumentException(
                    String.format(
                            "Dimension value cannot be greater than [%s] but got [%s] for vector [%s]",
                            LUCENE_MAX_DIMENSION,
                            dimension,
                            input.getName()
                    )
            );
        }

        this.fieldType = KnnVectorField.createFieldType(dimension, vectorSimilarityFunction);

        if (this.hasDocValues) {
            this.vectorFieldType = buildDocValuesFieldType();
        } else {
            this.vectorFieldType = null;
        }
    }

    private static FieldType buildDocValuesFieldType() {
        FieldType field = new FieldType();
        field.setDocValuesType(DocValuesType.BINARY);
        field.freeze();
        return field;
    }

    @Override
    protected void parseCreateField(ParseContext context, int dimension) throws IOException {
        Optional<float[]> arrayOptional = getFloatsFromContext(context, dimension);

        if (arrayOptional.isEmpty()) {
            return;
        }
        final float[] array = arrayOptional.get();

        KnnVectorField point = new KnnVectorField(name(), array, fieldType);

        context.doc().add(point);
        if (fieldType.stored()) {
            context.doc().add(new StoredField(name(), point.toString()));
        }
        if (hasDocValues && vectorFieldType != null) {
            context.doc().add(new VectorField(name(), array, vectorFieldType));
        }
        context.path().remove();
    }

    static class CreateLuceneFieldMapperInput {
        String name;

        CorrelationVectorFieldType mappedFieldType;

        MultiFields multiFields;

        CopyTo copyTo;

        Explicit<Boolean> ignoreMalformed;
        boolean stored;
        boolean hasDocValues;

        CorrelationParamsContext correlationParams;

        public CreateLuceneFieldMapperInput(String name,
                                            CorrelationVectorFieldType mappedFieldType,
                                            MultiFields multiFields,
                                            CopyTo copyTo,
                                            Explicit<Boolean> ignoreMalformed,
                                            boolean stored,
                                            boolean hasDocValues,
                                            CorrelationParamsContext correlationParams) {
            this.name = name;
            this.mappedFieldType = mappedFieldType;
            this.multiFields = multiFields;
            this.copyTo = copyTo;
            this.ignoreMalformed = ignoreMalformed;
            this.stored = stored;
            this.hasDocValues = hasDocValues;
            this.correlationParams = correlationParams;
        }

        public String getName() {
            return name;
        }

        public CorrelationVectorFieldType getMappedFieldType() {
            return mappedFieldType;
        }

        public MultiFields getMultiFields() {
            return multiFields;
        }

        public CopyTo getCopyTo() {
            return copyTo;
        }

        public Explicit<Boolean> getIgnoreMalformed() {
            return ignoreMalformed;
        }

        public boolean isStored() {
            return stored;
        }

        public boolean isHasDocValues() {
            return hasDocValues;
        }

        public CorrelationParamsContext getCorrelationParams() {
            return correlationParams;
        }
    }
}