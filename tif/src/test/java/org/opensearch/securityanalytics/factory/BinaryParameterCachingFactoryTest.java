package org.opensearch.securityanalytics.factory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class BinaryParameterCachingFactoryTest {
    private static final String PARAMETER1 = UUID.randomUUID().toString();
    private static final String PARAMETER2 = UUID.randomUUID().toString();
    private static final String VALUE1 = UUID.randomUUID().toString();
    private static final String PARAMETER3 = UUID.randomUUID().toString();
    private static final String PARAMETER4 = UUID.randomUUID().toString();
    private static final String VALUE2 = UUID.randomUUID().toString();

    @Mock
    private static Map<String, String> innerFactoryValues;
    @Mock
    private static Map<String, Map<String, String>> factoryValues;

    private BinaryParameterCachingFactory<String, String, String> factory;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        factory = new TestBinaryParameterCachingFactory();

        when(factoryValues.get(eq(PARAMETER1))).thenReturn(innerFactoryValues);
        when(innerFactoryValues.get(eq(PARAMETER2))).thenReturn(VALUE1);
        when(factoryValues.get(eq(PARAMETER3))).thenReturn(innerFactoryValues);
        when(innerFactoryValues.get(eq(PARAMETER4))).thenReturn(VALUE2);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(factoryValues, innerFactoryValues);
    }

    @Test
    public void testCreate_callsDoCreateIfNoCache() {
        assertEquals(VALUE1, factory.create(PARAMETER1, PARAMETER2));

        verify(factoryValues).get(eq(PARAMETER1));
        verify(innerFactoryValues).get(eq(PARAMETER2));
    }

    @Test
    public void testCreate_fetchesCachedValueIfPresent() {
        assertEquals(VALUE1, factory.create(PARAMETER1, PARAMETER2));
        assertEquals(VALUE1, factory.create(PARAMETER1, PARAMETER2));

        verify(factoryValues).get(eq(PARAMETER1));
        verify(innerFactoryValues).get(eq(PARAMETER2));
    }

    @Test
    public void testCreate_callsDoCreateForNewCacheEntry() {
        assertEquals(VALUE1, factory.create(PARAMETER1, PARAMETER2));
        assertEquals(VALUE2, factory.create(PARAMETER3, PARAMETER4));

        verify(factoryValues).get(eq(PARAMETER1));
        verify(innerFactoryValues).get(eq(PARAMETER2));
        verify(factoryValues).get(eq(PARAMETER3));
        verify(innerFactoryValues).get(eq(PARAMETER4));
    }

    @Test
    public void testCreate_ContinuouslyReturnsCachedValue() {
        final int calls = new Random().nextInt(100);

        for (int i = 0; i < calls; i++) {
            assertEquals(VALUE1, factory.create(PARAMETER1, PARAMETER2));
            assertEquals(VALUE2, factory.create(PARAMETER3, PARAMETER4));
        }

        verify(factoryValues).get(eq(PARAMETER1));
        verify(innerFactoryValues).get(eq(PARAMETER2));
        verify(factoryValues).get(eq(PARAMETER3));
        verify(innerFactoryValues).get(eq(PARAMETER4));
    }

    @Test
    public void testCreate_NullValue() {
        final String randomValue = UUID.randomUUID().toString();
        when(factoryValues.get(eq(randomValue))).thenReturn(innerFactoryValues);

        assertThrows(NullPointerException.class, () -> factory.create(randomValue, randomValue));

        verify(factoryValues).get(eq(randomValue));
        verify(innerFactoryValues).get(eq(randomValue));
    }

    private static class TestBinaryParameterCachingFactory extends BinaryParameterCachingFactory<String, String, String> {
        @Override
        protected String doCreate(final String param1, final String param2) {
            return factoryValues.get(param1).get(param2);
        }
    }
}
