package dod.p1.kc.routing.deployment.blocks;

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

public class RecursiveBlockThroughTest {

  // @RegisterExtension
  // static final QuarkusUnitTest config = new QuarkusUnitTest();
  /**
   * the HTTP_BAD_REQUEST.
   */
  public static final int HTTP_BAD_REQUEST = 400;
  /**
   * the HTTP_NOT_FOUND.
   */
  public static final int HTTP_NOT_FOUND = 404;
  /**
   * the HTTP_SUCCESS.
   */
  public static final int HTTP_SUCCESS = 200;


  @RegisterExtension
  static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
          .addAsResource(new StringAsset(
                  //Should block
                  "quarkus.kc-routing.path-recursive-block./TestWebServer=9006\n" +
                  //Should only allow subpath
                  "quarkus.kc-routing.path-allow./TestWebServer/suballowpath=127.0.0.0/8\n" +
                  //Wrong port, should not block traffic listening on 9006
                  "quarkus.kc-routing.path-recursive-block./TestWebServer2=9005\n" +
                  //Should allow due to allow rule below
                  "quarkus.kc-routing.path-recursive-block./TestWebServer3=9004,9005,9006\n" +
                  "quarkus.kc-routing.path-recursive-block./TestWebServer3/sub=9004,9005,9006\n" +
                  //Allow set to all of loopback CIDR should allow
                  "quarkus.kc-routing.path-allow./TestWebServer3=127.0.0.0/8\n"),
                  "application.properties"));

  @Route(path = "TestWebServer")
  void ping(RoutingContext rc) {
      if (rc.request().query() != null){
        rc.response().end("parameters="+rc.request().query());
      }else {
        rc.response().end("No parameters provided");
      }
  }
  @Route(path = "TestWebServer2")
  void ping2(RoutingContext rc) {
      if (rc.request().query() != null){
        rc.response().end("parameters="+rc.request().query());
      }else {
        rc.response().end("No parameters provided");
      }
  }
  @Route(path = "TestWebServer3")
  void ping3(RoutingContext rc) {
      if (rc.request().query() != null){
        rc.response().end("parameters="+rc.request().query());
      }else {
        rc.response().end("No parameters provided");
      }
  }
  @Test
  public void testBlock() {
    RestAssured.when().get("http://localhost:9006/TestWebServer").then().statusCode(HTTP_BAD_REQUEST);
  }

  @Test
  public void testRouteThru() {
    RestAssured.when().get("http://localhost:9006/TestWebServer2").then().statusCode(HTTP_SUCCESS);
  }

  @Test
  public void testNonBlockPath() {
    RestAssured.when().get("http://localhost:9006/ShouldRoute").then().statusCode(HTTP_NOT_FOUND);
  }

  //Should block
  @Test
  public void testBlockPathWithParameters() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  //Should block due to being recursive, but no landing page
  @Test
  public void testBlockPathWithParametersWithSubpath() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer/subpath")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  //Should not block due to path-blocks not being recursive, but no landing page
  @Test
  public void testBlockPathWithParametersWithAllowedSubpath() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer/suballowpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testNonBlockPathWithParameters() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer2")
      .then().statusCode(HTTP_SUCCESS)
      .body(is("parameters=testvar1=1&testvar2=2"));

  }
  @Test
  public void testBlockWithAllow() {
    given()
      .when()
      .get("http://localhost:9006/TestWebServer3")
      .then().statusCode(HTTP_SUCCESS)
      .body(is("No parameters provided"));
  }
  @Test
  public void testBlockWithAllowWithParameters() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer3")
      .then().statusCode(HTTP_SUCCESS)
      .body(is("parameters=testvar1=1&testvar2=2"));
  }
  @Test
  public void testBlockWithAllowWithParametersWithSlash() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer3/")
      .then().statusCode(HTTP_SUCCESS)
      .body(is("parameters=testvar1=1&testvar2=2"));
  }
  //Should not block due to allow, but should return NOT FOUND due to no landing page
  @Test
  public void testBlockWithAllowWithParametersWithSubPath() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer3/subpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  //Should not block due to allow, but should return NOT FOUND due to no landing page
  @Test
  public void testBlockWithAllowWithParametersWithDeclaredSubPath() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .get("http://localhost:9006/TestWebServer3/sub")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
}
