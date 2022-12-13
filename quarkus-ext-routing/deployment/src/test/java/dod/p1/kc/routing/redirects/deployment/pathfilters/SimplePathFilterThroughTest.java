package dod.p1.kc.routing.redirects.deployment.pathfilters;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.hamcrest.Matchers.containsString;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.vertx.ext.web.RoutingContext;
import org.jboss.logging.Logger;

public class SimplePathFilterThroughTest {

  private static final Logger LOGGER = Logger.getLogger(SimplePathFilterThroughTest.class.getName());

  // @RegisterExtension
  // static final QuarkusUnitTest config = new QuarkusUnitTest();

  @RegisterExtension
  static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
          .addAsResource(new StringAsset(
                  "quarkus.kc-routing-redirects.path-filters./first=/testwebserver1\n" +
                  "quarkus.kc-routing-redirects.path-filters./first/second=/testwebserver1\n" +
                  "quarkus.kc-routing-redirects.path-filters./first/subpath1=/testwebserver1/subpath1/subpath2\n"),
                  "application.properties"));

  @Route(path = "/testwebserver1")
  void webserver(RoutingContext rc) {
      if (rc.request().query() != null){
        rc.response().end("parameters="+rc.request().query());
      }else {
        rc.response().end("No parameters provided");
      }
  }

  @Route(path = "/testwebserver1/subpath1/subpath2")
  void webserver_second(RoutingContext rc) {
      if (rc.request().query() != null){
        rc.response().end("(2) parameters="+rc.request().query());
      }else {
        rc.response().end("(2) No parameters provided");
      }
  }

  @Test
  public void testSingleWithOutParameters() {
    given()
      .when()
      .get("http://localhost:9006/first")
      .then().statusCode(200)
      .body(is("No parameters provided"));

  }

  @Test
  public void testDoubleWithOutParameters() {
    given()
      .when()
      .get("http://localhost:9006/first/second")
      .then().statusCode(200)
      .body(is("No parameters provided"));

  }

  @Test
  public void testDoubletoSingleWithParameters() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/first/second")
      .then().statusCode(200)
      .body(is("parameters=testvar1=1&testvar2=2"));

  }

  //Expecting for "first" to be replaced with "webserver" and subpath to stay the same.
  @Test
  public void testDoubletoTripleWithOutParameters() {
    given()
      .when()
      .get("http://localhost:9006/first/subpath1")
      .then().statusCode(200)
      .body(is("(2) No parameters provided"));

  }

}
