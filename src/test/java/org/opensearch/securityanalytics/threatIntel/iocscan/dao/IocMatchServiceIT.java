package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.opensearch.action.LatchedActionListener;
import org.opensearch.action.StepListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.util.concurrent.CountDown;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.SecurityAnalyticsIntegTestCase;
import org.opensearch.securityanalytics.model.threatintel.IocMatch;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;


public class IocMatchServiceIT extends SecurityAnalyticsIntegTestCase {

    public void test_indexIocMatches() throws InterruptedException {
        IocMatchService service = new IocMatchService(client(), clusterService());
        List<IocMatch> iocMatches = generateIocMatches(10);
        CountDown countdown = new CountDown(1);
        service.indexIocMatches(iocMatches, ActionListener.wrap(r -> {
            countdown.countDown();
        }, e -> {
            logger.error("failed to index ioc matches", e);
            fail();
            countdown.countDown();
        }));
        SearchRequest request = new SearchRequest(IocMatchService.INDEX_NAME);
        request.source().size(10);
        CountDown countDownLatch1 = new CountDown(1);
        client().search(request, ActionListener.wrap(
                response -> {
                    assertEquals(response.getHits().getHits().length, 10);
                    countDownLatch1.countDown();
                },
                e -> {
                    logger.error("failed to search indexed ioc matches", e);
                    fail();
                    countDownLatch1.countDown();
                }

        ));
        countDownLatch1.isCountedDown();
    }

    private List<IocMatch> generateIocMatches(int i) {
        List<IocMatch> iocMatches = new ArrayList<>();
        String monitorId = randomAlphaOfLength(10);
        String monitorName = randomAlphaOfLength(10);
        for (int i1 = 0; i1 < i; i1++) {
            iocMatches.add(new IocMatch(
                    randomAlphaOfLength(10),
                    randomList(1, 10, () -> randomAlphaOfLength(10)),//docids
                    randomList(1, 10, () -> randomAlphaOfLength(10)), //feedids
                    monitorId,
                    monitorName,
                    randomAlphaOfLength(10),
                    "IP",
                    Instant.now(),
                    randomAlphaOfLength(10)
            ));
        }
        return iocMatches;
    }
}