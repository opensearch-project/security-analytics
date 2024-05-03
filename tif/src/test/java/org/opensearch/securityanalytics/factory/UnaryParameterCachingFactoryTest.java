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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class UnaryParameterCachingFactoryTest {
    private static final String PARAMETER1 = UUID.randomUUID().toString();
    private static final String VALUE1 = UUID.randomUUID().toString();
    private static final String PARAMETER2 = UUID.randomUUID().toString();
    private static final String VALUE2 = UUID.randomUUID().toString();

    @Mock
    private static Map<String, String> factoryValues;

    private UnaryParameterCachingFactory<String, String> factory;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        factory = new TestUnaryParameterCachingFactory();

        when(factoryValues.get(eq(PARAMETER1))).thenReturn(VALUE1);
        when(factoryValues.get(eq(PARAMETER2))).thenReturn(VALUE2);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(factoryValues);
    }

    @Test
    public void testCreate_callsDoCreateIfNoCache() {
        assertEquals(VALUE1, factory.create(PARAMETER1));

        verify(factoryValues).get(eq(PARAMETER1));
    }

    @Test
    public void testCreate_fetchesCachedValueIfPresent() {
        assertEquals(VALUE1, factory.create(PARAMETER1));
        assertEquals(VALUE1, factory.create(PARAMETER1));

        verify(factoryValues).get(eq(PARAMETER1));
    }

    @Test
    public void testCreate_callsDoCreateForNewCacheEntry() {
        assertEquals(VALUE1, factory.create(PARAMETER1));
        assertEquals(VALUE2, factory.create(PARAMETER2));

        verify(factoryValues).get(eq(PARAMETER1));
        verify(factoryValues).get(eq(PARAMETER2));
    }

    @Test
    public void testCreate_ContinuouslyReturnsCachedValue() {
        final int calls = new Random().nextInt(100);

        for (int i = 0; i < calls; i++) {
            assertEquals(VALUE1, factory.create(PARAMETER1));
            assertEquals(VALUE2, factory.create(PARAMETER2));
        }

        verify(factoryValues).get(eq(PARAMETER1));
        verify(factoryValues).get(eq(PARAMETER2));
    }

    @Test
    public void testCreate_NullValue() {
        final String randomValue = UUID.randomUUID().toString();
        assertThrows(NullPointerException.class, () -> factory.create(randomValue));

        verify(factoryValues).get(eq(randomValue));
    }

    private static class TestUnaryParameterCachingFactory extends UnaryParameterCachingFactory<String, String> {
        @Override
        protected String doCreate(final String param) {
            return factoryValues.get(param);
        }
    }
}
