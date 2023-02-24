package dod.p1.kc.routing.deployment.blocks;

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

public class RecursiveBlockTest {

  /**
   * the HTTP_BAD_REQUEST.
   */
  public static final int HTTP_BAD_REQUEST = 400;
  /**
   * the HTTP_NOT_FOUND.
   */
  public static final int HTTP_NOT_FOUND = 404;

  // @RegisterExtension
  // static final QuarkusUnitTest config = new QuarkusUnitTest();
  @RegisterExtension
  static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
          .addAsResource(new StringAsset(
                  "quarkus.kc-routing.path-recursive-block./recursiveblock1=9006\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock11=9005\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock111/=9006\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock2/=9006\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock3/subpath=9006\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock4=9005,9006\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock5=9006,9005\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock6/=9005,9006\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock7/subpath=9006,9005\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock8=9004,9005\n" +
                  "quarkus.kc-routing.path-recursive-block./recursiveblock9/subpath=9004,9005\n"),
                  "application.properties"));
  @Test
  public void testStraight() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock1")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testStraightWithSlash() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock1/")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testSubPath() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock1/shouldBlock")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testSubPathWithSlash() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock1/shouldBlock/")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testSimilarPathName() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock10")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testSimilarPathOnDiffPortBlock() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock11")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testSimilarPathBetweenRoutes() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock111")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithSlash() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock2/")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithSubpath() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock3/subpath")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPorts() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock4")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsSwapped() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock5")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsAndSlash() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock6/")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsAndSubpath() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock7/subpath")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  // Below tests should all pass through without being blocked
  @Test
  public void testWrongCase() {
    given()
      .when()
      .get("http://localhost:9006/RecursiveBlock1")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }

  @Test
  public void testNonRoute() {
    given()
      .when()
      .get("http://localhost:9006/shouldNotBlock")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsNonPortMatch() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock8")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testSubpathMultiPortsNonPortMatch() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock9/subpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }

}
