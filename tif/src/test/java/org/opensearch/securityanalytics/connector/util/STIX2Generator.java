package org.opensearch.securityanalytics.connector.util;

import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.STIX2;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class STIX2Generator {
    public List<IOC> generateSTIX2(final int count) {
        return generateSTIX2(count, i -> randomSTIX2());
    }

    public List<IOC> generateSTIX2(final int count, final String feedId) {
        return generateSTIX2(count, i -> randomSTIX2(feedId));
    }

    public List<IOC> generateSTIX2(final int count, final Function<Integer, STIX2> generatorFunction) {
        return IntStream.range(0, count)
                .mapToObj(generatorFunction::apply)
                .collect(Collectors.toList());
    }

    public STIX2 randomSTIX2() {
        return randomSTIX2(UUID.randomUUID().toString());
    }

    public STIX2 randomSTIX2(final String feedId) {
        final STIX2 ioc = new STIX2();
        ioc.setId(UUID.randomUUID().toString());
        ioc.setFeedId(feedId);
        ioc.setSpecVersion(UUID.randomUUID().toString());
        ioc.setType(UUID.randomUUID().toString());

        return ioc;
    }
}
