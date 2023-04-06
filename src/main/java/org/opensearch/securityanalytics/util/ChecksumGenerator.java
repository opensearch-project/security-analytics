package org.opensearch.securityanalytics.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ChecksumGenerator {

    private static int CHUNK_SIZE = 4096;

    public static String checksumFile(Path file) throws IOException, NoSuchAlgorithmException {
        String md5hash = null;
        try ( InputStream is = new FileInputStream(file.toFile()) ) {
            MessageDigest md5Crypt = MessageDigest.getInstance("MD5");

            byte[] buffer = new byte[CHUNK_SIZE];

            int read;
            while((read = is.read(buffer)) > 0) {
                md5Crypt.update(buffer,0,read);
            }
            return new BigInteger(1, md5Crypt.digest()).toString(16);
        }
    }

    public static String checksumString(String payload) {
        try {
            MessageDigest md5Crypt = MessageDigest.getInstance("MD5");
            md5Crypt.update(payload.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, md5Crypt.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

}
