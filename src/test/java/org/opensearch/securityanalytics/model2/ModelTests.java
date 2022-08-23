/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model2;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.io.stream.BytesStreamInput;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.lang.reflect.Field;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model2.ModelSerializer.checkType;
import static org.opensearch.securityanalytics.model2.ModelSerializer.getListGeneric;

public class ModelTests extends OpenSearchTestCase {

    private static final Logger LOG = LogManager.getLogger(ModelTests.class);

    public static final List<Class<?>> TEST_MODELS = new SecurityAnalyticsPlugin().getNamedXContent().stream().map(x -> x.categoryClass).collect(Collectors.toList());

    private static final int NULL_FIELD_PROBABILITY = 10;
    private static final List<String> ALPHABET = List.of("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "_", "-");

    public void testModels() throws Exception {
        final Random random = new Random();
        final long seed = random.nextInt();
        for (Class<?> modelClass : TEST_MODELS) {
            LOG.info("Testing {}", modelClass.getName());
            // TODO make model instance population parameterized
            final Object modelA = createModel(new Random(seed), modelClass);
            final Object modelB = createModel(new Random(seed), modelClass);
            final Object modelC = createModel(random, modelClass);
            final Object modelD = createModel(random, modelClass);
            LOG.info("\tModel instances: \n\tmodelA: {}\n\tmodelB: {}\n\tmodelC: {}\n\tmodelD: {}", modelA, modelB, modelC, modelD);
            assertEquals(modelA, modelB);
            assertNotEquals(modelA, modelC);
            assertNotEquals(modelA, modelD);
            assertNotEquals(modelB, modelC);
            assertNotEquals(modelB, modelD);
            assertNotEquals(modelC, modelD);
            assertEquals(modelA.hashCode(), modelB.hashCode());
            assertEquals(3, new HashSet<>(List.of(modelA, modelB, modelC, modelD)).size());

            LOG.info("\tVerifying stream input/output serialization consistency for {}", modelClass);
            // TODO: test against all stream output/input types
            assertEquals(modelA, ModelTests.serializeDeserialize((ToXContentModel) modelA));
            for (final Field field : ModelSerializer.getSortedFields(modelClass)) {
                assertEquals(field.get(modelA), field.get(modelB));
            }

            // TODO: test XContent parser/builder
        }
    }

    public static <T> T createModel(final Random random, final Class<T> modelClass) {
        try {
            final T model = modelClass.getConstructor().newInstance();
            for (final Field field : ModelSerializer.getSortedFields(modelClass)) {
                final boolean isNull = random.nextInt(100) < NULL_FIELD_PROBABILITY;
                if (!isNull) {
                    if (checkType(field, boolean.class))
                        field.set(model, random.nextBoolean());
                    else if (checkType(field, String.class))
                        field.set(model, nextString(random));
                    else if (checkType(field, long.class))
                        field.set(model, random.nextLong());
                    else if (checkType(field, int.class))
                        field.set(model, random.nextInt());
                    else if (checkType(field, TimeValue.class))
                        field.set(model, new TimeValue(Math.abs(random.nextLong())));
                    else if (checkType(field, ChronoUnit.class))
                        field.set(model, ChronoUnit.values()[random.nextInt(ChronoUnit.values().length)]);
                    else if (checkType(field, List.class, String.class))
                        field.set(model, nextListString(random));
                    else if (checkType(field, List.class))
                        field.set(model, nextList(random, getListGeneric(field)));
                    else if (checkType(field, ToXContentModel.class))
                        field.set(model, createModel(random, field.getType()));
                }
            }
            return model;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String nextString(final Random random) {
        final int length = random.nextInt(10) + 1;
        String string = "";
        for (int i = 0; i < length; i++) {
            string = string + ALPHABET.get(random.nextInt(ALPHABET.size()));
        }
        return string;
    }

    public static List<String> nextListString(final Random random) {
        final int length = random.nextInt(10) + 1;
        final List<String> list = new ArrayList<>();
        for (int i = 0; i < length; i++) {
            list.add(nextString(random));
        }
        return list;
    }

    public static <T> List<T> nextList(final Random random, final Class<T> type) {
        final int length = random.nextInt(10) + 1;
        final List<T> list = new ArrayList<>();
        for (int i = 0; i < length; i++) {
            list.add(createModel(random, type));
        }
        return list;
    }

    public static <T extends ToXContentModel> T serializeDeserialize(final T model) {
        try {
            final BytesStreamOutput output = new BytesStreamOutput();
            ModelSerializer.write(output, model);
            final BytesStreamInput input = new BytesStreamInput(output.bytes().toBytesRef().bytes);
            return ModelSerializer.read(input, (Class<T>) model.getClass());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T extends ToXContentModel> T xcontentReadWrite(final T model) {
        try {
            final BytesStreamOutput output = new BytesStreamOutput();
            ModelSerializer.write(output, model);
            final BytesStreamInput input = new BytesStreamInput(output.bytes().toBytesRef().bytes);
            return ModelSerializer.read(input, (Class<T>) model.getClass());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

}
