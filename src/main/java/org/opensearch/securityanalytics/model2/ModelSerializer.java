/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model2;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

public class ModelSerializer {

    private static final Logger LOG = LogManager.getLogger(ModelSerializer.class);

    private ModelSerializer() {
        // do nothing
    }

    public static class ReaderWriter<T> implements Writeable.Reader<T>, Writeable.Writer<T> {

        private final Class<T> modelClass;

        public ReaderWriter(final Class<T> modelClass) {
            this.modelClass = modelClass;
        }

        @Override
        public T read(final StreamInput input) throws IOException {
            return ModelSerializer.read(input, this.modelClass);
        }

        @Override
        public void write(final StreamOutput output, final T t) throws IOException {
            ModelSerializer.write(output, t);
        }
    }

    public static <T> XContentBuilder write(final XContentBuilder builder, final T model) throws IOException {
        builder.startObject();
        try {
            for (final Field field : ModelSerializer.getSortedFields(model.getClass())) {
                builder.field(field.getName(), field.get(model));
            }
        } catch (IllegalAccessException e) {
            throw new IOException(e);
        }
        builder.endObject();
        return builder;
    }

    public static <T> T read(final XContentParser parser, final Class modelClass) throws IOException {
        try {
            final T model = (T) modelClass.getConstructor().newInstance();
            for (final Field field : ModelSerializer.getSortedFields(model.getClass())) {
                final String fieldName = parser.currentName();
                assert field.getName().equals(fieldName);
                parser.nextToken();
                if (checkType(field, Boolean.class))
                    field.set(model, parser.booleanValue());
                else if (checkType(field, String.class))
                    field.set(model, parser.text());
                else if (checkType(field, Long.class))
                    field.set(model, parser.longValue());
                else if (checkType(field, Integer.class))
                    field.set(model, parser.intValue());
                else if (checkType(field, TimeValue.class))
                    field.set(model, new TimeValue(parser.longValue()));
                else if (checkType(field, ChronoUnit.class))
                    field.set(model, ChronoUnit.valueOf(parser.text()));
                else if (checkType(field, List.class))
                    field.set(model, parser.list());
                else if (checkType(field, ToXContentObject.class))
                    field.set(model, parser.objectBytes());
                else
                    throw new IllegalArgumentException(String.format(Locale.getDefault(), "Unsupported field type %s in model %s", field.getType().getName(), model.getClass().getSimpleName()));
            }
            return model;
        } catch (final Exception e) {
            if (e instanceof IOException)
                throw (IOException) e;
            else
                throw new IOException(e);
        }
    }

    public static <T> void write(final StreamOutput output, final T model) throws IOException {
        try {
            // output.writeString(model.getClass().getName());
            for (final Field field : ModelSerializer.getSortedFields(model.getClass())) {
                if (null == field.get(model))
                    output.writeBoolean(false);
                else {
                    output.writeBoolean(true);
                    if (checkType(field, boolean.class))
                        output.writeBoolean(field.getBoolean(model));
                    else if (checkType(field, String.class))
                        output.writeString((String) field.get(model));
                    else if (checkType(field, long.class))
                        output.writeLong(field.getLong(model));
                    else if (checkType(field, int.class))
                        output.writeInt(field.getInt(model));
                    else if (checkType(field, TimeValue.class))
                        output.writeTimeValue((TimeValue) field.get(model));
                    else if (checkType(field, ChronoUnit.class))
                        output.writeEnum((ChronoUnit) field.get(model));
                    else if (checkType(field, List.class, String.class))
                        output.writeStringCollection((List<String>) field.get(model));
                    else if (checkType(field, List.class)) {
                        List list = (List) field.get(model);
                        output.writeInt(list.size());
                        for (final Object obj : list) {
                            ModelSerializer.write(output, obj);
                        }
                    } else if (checkType(field, ToXContentObject.class))
                        ModelSerializer.write(output, field.get(model));
                    else
                        throw new IllegalArgumentException(String.format(Locale.getDefault(), "Unsupported field type %s in model %s", field.getType().getName(), model.getClass().getSimpleName()));
                }
            }
        } catch (IllegalAccessException e) {
            throw new IOException(e);
        }
    }


    public static <T> T read(final StreamInput input, final Class<T> modelClass) throws IOException {
        try {
            //final Class<T> modelClassCalc = (Class<T>) Class.forName(input.readString());
            final T model = modelClass.getConstructor().newInstance();
            for (final Field field : ModelSerializer.getSortedFields(modelClass)) {
                final boolean exists = input.readBoolean();
                if (exists) {
                    if (checkType(field, boolean.class))
                        field.set(model, input.readBoolean());
                    else if (checkType(field, String.class))
                        field.set(model, input.readString());
                    else if (checkType(field, long.class))
                        field.set(model, input.readLong());
                    else if (checkType(field, int.class))
                        field.set(model, input.readInt());
                    else if (checkType(field, TimeValue.class))
                        field.set(model, input.readTimeValue());
                    else if (checkType(field, ChronoUnit.class))
                        field.set(model, input.readEnum(ChronoUnit.class));
                    else if (checkType(field, List.class, String.class))
                        field.set(model, input.readStringList());
                    else if (checkType(field, List.class)) {
                        final int size = input.readInt();
                        final List list = new ArrayList();
                        for (int i = 0; i < size; i++) {
                            list.add(ModelSerializer.read(input, getListGeneric(field)));
                        }
                        field.set(model, list);
                    } else if (checkType(field, ToXContentObject.class))
                        field.set(model, ModelSerializer.read(input, field.getType()));
                    else
                        throw new IllegalArgumentException(String.format(Locale.getDefault(), "Unsupported field type %s in model %s", field.getType().getName(), model.getClass().getSimpleName()));
                }
            }
            return model;
        } catch (final Exception e) {
            if (e instanceof IOException)
                throw (IOException) e;
            else
                throw new IOException(e);
        }
    }

    public static int getHashCode(final Object object) {
        return ModelSerializer.getSortedFields(object.getClass())
                .stream()
                .map(field -> {
                    try {
                        return Objects.hashCode(field.get(object));
                    } catch (final Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .reduce((a, b) -> a ^ b).orElseThrow();
    }

    public static String getString(final Object object) {
        final StringBuilder builder = new StringBuilder(object.getClass().getSimpleName()).append("[");
        ModelSerializer.getSortedFields(object.getClass())
                .forEach(field -> {
                    try {
                        builder.append(field.getName()).append("=").append(field.get(object)).append(",");
                    } catch (final Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        builder.deleteCharAt(builder.length() - 1);
        builder.append("]");
        return builder.toString();
    }

    public static boolean areEquals(final Object a, final Object b) {
        if (!a.getClass().equals(b.getClass()))
            return false;
        return ModelSerializer.getSortedFields(a.getClass())
                .stream()
                .allMatch(field -> {
                    try {
                        return Objects.equals(field.get(a), field.get(b));
                    } catch (final NullPointerException e1) {
                        return false;
                    } catch (final Exception e2) {
                        throw new RuntimeException(e2);
                    }
                });
    }

    public static List<Field> getSortedFields(final Class<?> modelClass) {
        return Arrays.stream(modelClass.getFields())
                .filter(field -> Modifier.isPublic(field.getModifiers()))
                .filter(field -> !Modifier.isStatic(field.getModifiers()))
                .sorted(Comparator.comparing(Field::getName))
                .collect(Collectors.toList());
    }

    public static boolean checkType(final Field check, final Class<?> against) {
        return against.isAssignableFrom(check.getType());
    }

    public static <T> Class<T> getListGeneric(final Field field) {
        if (!(field.getGenericType() instanceof ParameterizedType))
            throw new IllegalArgumentException();
        try {
            final ParameterizedType paramType = (ParameterizedType) field.getGenericType();
            return (Class<T>) Class.forName(paramType.getActualTypeArguments()[0].getTypeName());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> boolean checkType(final Field check, final Class<? extends Collection> collection,
                                        final Class<T> elements) {
        try {
            if (!(check.getGenericType() instanceof ParameterizedType))
                return false;
            final ParameterizedType paramType = (ParameterizedType) check.getGenericType();
            return collection.isAssignableFrom(Class.forName(paramType.getRawType().getTypeName())) &&
                    elements.isAssignableFrom(Class.forName(paramType.getActualTypeArguments()[0].getTypeName()));
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}