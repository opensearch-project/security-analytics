package org.opensearch.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gatling.javaapi.core.CoreDsl;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpDsl;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * @author Grant Haywood (<a href="http://iowntheinter.net">http://iowntheinter.net</a>)
 */
public class OneFiftyRules10KDocs extends Simulation {

    Map.Entry<Integer, Integer> EXECUTIONS_DOCRATE = Map.entry(150, 10000);
    List<String> createdRules = new ArrayList<>();
    private final String baseURI = "http://localhost:9200";
    final int CONCURRENT_USERS = 500;

    @Override
    public void before() {
        //Create the rules
        IntStream.range(0, EXECUTIONS_DOCRATE.getKey()).forEach(i -> {
            try {
                CloseableHttpClient client = HttpClients.createDefault();
                HttpPost post = new HttpPost(String.format("%s/_plugins/_security_analytics/rules?category=windows", baseURI));
                post.setHeader("Content-Type", "application/json");
                post.setEntity(new StringEntity(Util.replaceLine(Util.readResource(Util.TEMPLATE_RULE), 16, String.format("    EventID: %d\n", i))));
                HttpResponse response = client.execute(post);
                if (response.getStatusLine().getStatusCode() != 201) {
                    System.err.println(response);
                    throw new RuntimeException("Failed to create rule");
                } else {
                    InputStream data = response.getEntity().getContent();
                    String responseJson = new String(data.readAllBytes());
                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> responseStruct = mapper.readValue(responseJson, Map.class);
                    createdRules.add((String) responseStruct.get("_id"));
                    System.out.println(String.format("created rule with id: %s", (String) responseStruct.get("_id")));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public void after() {
        //Delete the rules
        createdRules.forEach(ruleId -> {
            final String deletePath = String.format("/_plugins/_security_analytics/rules/%s", ruleId);
            try {
                System.out.println(deletePath);
                CloseableHttpClient client = HttpClients.createDefault();
                HttpDelete del = new HttpDelete(String.format("%s%s", baseURI, deletePath));
                HttpResponse response = client.execute(del);
                if (response.getStatusLine().getStatusCode() != 200) {
                    System.err.println(response);
                    throw new RuntimeException("Failed to delete rule");
                } else {
                    System.out.println(String.format("removed rule with id: %s", ruleId));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    {
        HttpProtocolBuilder httpProtocol = HttpDsl.http
                .baseUrl("http://127.0.0.1:9200")
                .inferHtmlResources()
                .acceptHeader("application/json")
                .acceptEncodingHeader("gzip")
                .userAgentHeader("Go-http-client/1.1");

        Map<CharSequence, String> headers_5 = new HashMap<>();
        headers_5.put("Content-Type", "application/json; charset=UTF-8");


        ScenarioBuilder scn = CoreDsl.scenario("RecordedSimulation")
                .feed(SimulationData.randomDataGenerator())
                .exec(
                        HttpDsl.http("sendDocument")
                                .post("/_bulk")
                                .headers(headers_5)
                                .body(CoreDsl.ElFileBody("dns_document.json"))
                                .basicAuth("admin", "admin")
                );


        setUp(scn.injectOpen(CoreDsl.constantUsersPerSec(CONCURRENT_USERS).during(Duration.ofMinutes(1))))
                .throttle(
                        CoreDsl.jumpToRps(EXECUTIONS_DOCRATE.getValue()),
                        CoreDsl.holdFor(Duration.ofSeconds(30))
                ).protocols(httpProtocol);
    }
}
