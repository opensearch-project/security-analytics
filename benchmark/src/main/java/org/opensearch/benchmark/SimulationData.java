package org.opensearch.benchmark;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author Grant Haywood (<a href="http://iowntheinter.net">http://iowntheinter.net</a>)
 */
public class SimulationData {
    public static final String RANDOM_IP = "RANDOM_IP";
    public static final String RANDOM_EVENT_ID = "RANDOM_EVENT_ID";

    public static Iterator<Map<String, Object>> randomDataGenerator() {
        return new Iterator<Map<String, Object>>() {
            @Override
            public boolean hasNext() {
                return true;
            }

            @Override
            public Map<String, Object> next() {
                return new HashMap<>() {{
                    put(RANDOM_IP, String.format("%d.%d.%d.%d",
                            Util.getRandomNumber(1, 255),
                            Util.getRandomNumber(1, 255),
                            Util.getRandomNumber(1, 255),
                            Util.getRandomNumber(1, 255)));
                    put(RANDOM_EVENT_ID, Util.getRandomNumber(1, 1000000));
                }};
            }
        };
    }
}
