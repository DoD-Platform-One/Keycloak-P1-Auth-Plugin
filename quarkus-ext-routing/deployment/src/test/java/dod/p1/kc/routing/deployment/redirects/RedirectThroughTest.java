package dod.p1.kc.routing.deployment.redirects;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.hamcrest.Matchers.containsString;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import io.quarkus.vertx.web.Route;
import io.quarkus.vertx.web.RouteBase;
import io.vertx.ext.web.RoutingContext;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

public class RedirectThroughTest {

  // @RegisterExtension
  // static final QuarkusUnitTest config = new QuarkusUnitTest();

  @RegisterExtension
  static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
          .addAsResource(new StringAsset(
                  // We need a real path that root points to for follows to work
                  "quarkus.kc-routing.path-redirect./Follow1=/TestWebServer\n" +
                  "quarkus.kc-routing.path-redirect./Follow2/SubPath=/TestWebServer\n" +
                  "quarkus.kc-routing.path-redirect./Follow3=/DoesNotExist\n"),
                  "application.properties"));

  @Route(path = "TestWebServer")
  void ping(RoutingContext rc) {
      if (rc.request().query() != null){
        rc.response().end("parameters="+rc.request().query());
      }else {
        rc.response().end("No parameters provided");
      }
  }
  @Test
  public void testOne() {
    RestAssured.when().get("http://localhost:9006/Follow1").then().statusCode(200);

  }

  @Test
  public void testTwo() {
    RestAssured.when().get("http://localhost:9006/Follow2/SubPath").then().statusCode(200);

  }

  @Test
  public void NotFoundTest() {
    RestAssured.when().get("http://localhost:9006/Follow3").then().statusCode(404);

  }

  @Test
  public void testWithOutParameters() {
    given()
      .when()
      .get("http://localhost:9006/Follow1")
      .then().statusCode(200)
      .body(is("No parameters provided"));

  }

  //Below test shows parameters are not passed with redirects
  @Test
  public void testWithParameters() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/Follow2/SubPath")
      .then().statusCode(200)
      .body(is("No parameters provided"));

  }
}
