package org.opensearch.benchmark;

import io.gatling.javaapi.core.*;
import io.gatling.javaapi.http.*;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.*;

public class CreateRule extends Simulation {

  {
    HttpProtocolBuilder httpProtocol = HttpDsl.http
      .baseUrl("http://localhost:9200")
      .inferHtmlResources()
      .acceptHeader("application/json, */*;q=0.5")
      .acceptEncodingHeader("gzip, deflate")
      .contentTypeHeader("application/json")
      .userAgentHeader("HTTPie/3.2.1");
    


    ScenarioBuilder scn = CoreDsl.scenario("RecordedSimulation")
      .exec(
        HttpDsl.http("request_0")
          .post("/_plugins/_security_analytics/rules?category=windows")
          .body(CoreDsl.RawFileBody("recordedsimulation/0000_request.json"))
      );

	  setUp(scn.injectOpen(CoreDsl.atOnceUsers(1))).protocols(httpProtocol);
  }
}
