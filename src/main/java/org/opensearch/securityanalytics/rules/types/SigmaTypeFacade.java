/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SigmaTypeFacade {

    private final Map<Class<?>, Class<? extends SigmaType>> typeMap;
    private static SigmaTypeFacade typeFacade;

    public SigmaTypeFacade() {
        typeMap = new HashMap<>();
        typeMap.put(Boolean.TYPE, SigmaBool.class);
        typeMap.put(Integer.TYPE, SigmaNumber.class);
        typeMap.put(Float.TYPE, SigmaNumber.class);
        typeMap.put(Long.TYPE, SigmaNumber.class);
        typeMap.put(Double.TYPE, SigmaNumber.class);
        typeMap.put(String.class, SigmaString.class);
        typeMap.put(Optional.empty().getClass(), SigmaNull.class);
    }

    public static SigmaType sigmaType(Object val) {
        if (typeFacade == null) {
            typeFacade = new SigmaTypeFacade();
        }

        if (val == null) {
            return new SigmaNull();
        } else if (val.getClass().equals(Boolean.class)) {
            return new SigmaBool((Boolean) val);
        } else if (val.getClass().equals(Integer.class)) {
            return new SigmaNumber((Integer) val);
        } else if (val.getClass().equals(Float.class)) {
            return new SigmaNumber((Float) val);
        } else if (val.getClass().equals(Long.class)) {
            return new SigmaNumber((Long) val);
        } else if (val.getClass().equals(Double.class)) {
            return new SigmaNumber((Double) val);
        } else if (val.getClass().equals(String.class)) {
            return new SigmaString((String) val);
        } else {
            return new SigmaNull();
        }
    }
}