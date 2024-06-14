package org.opensearch.benchmark;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;


/**
 * @author Grant Haywood (<a href="http://iowntheinter.net">http://iowntheinter.net</a>)
 */


public class Util {
    public static final String TEMPLATE_RULE = "templaterule.yml";

    public static int getRandomNumber(int min, int max) {
        return (int) ((Math.random() * (max - min)) + min);
    }


    public static String readResource(String name) throws IOException {
        try (InputStream inputStream = Util.class.getClassLoader().getResourceAsStream(name)) {
            if (inputStream == null) {
                throw new IOException("Resource not found: " + name);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        }
    }
    public static String replaceLine(String source, int line, String newLine){
        String[] lines = source.split("\r\n|\r|\n");
        lines[line] = newLine;
        return String.join("\n", lines);
    }

}
