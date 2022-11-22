package org.opensearch.benchmark;

import org.junit.Test;
import org.opensearch.benchmark.Util;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

/**
 * @author Grant Haywood (<a href="http://iowntheinter.net">http://iowntheinter.net</a>)
 */
public class UtilTest {
    @Test
    public void testReadResource() throws Exception {
        String resource = Util.readResource(Util.TEMPLATE_RULE);
        System.out.println(resource);
    }

    @Test
    public void testReplaceLine() throws IOException {
        String result = Util.replaceLine(Util.readResource(Util.TEMPLATE_RULE), 4, "abc");
        assertEquals("abc", result.split("\n")[4]);
    }
}
