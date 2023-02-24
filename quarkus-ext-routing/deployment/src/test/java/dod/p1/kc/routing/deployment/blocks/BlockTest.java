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

public class BlockTest {

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
                  "quarkus.kc-routing.path-block./block1=9006\n" +
                  "quarkus.kc-routing.path-block./block2/=9006\n" +
                  "quarkus.kc-routing.path-block./block3/subpath=9006\n" +
                  "quarkus.kc-routing.path-block./block4=9005,9006\n" +
                  "quarkus.kc-routing.path-block./block5=9006,9005\n" +
                  "quarkus.kc-routing.path-block./block6/=9005,9006\n" +
                  "quarkus.kc-routing.path-block./block7/subpath=9006,9005\n" +
                  "quarkus.kc-routing.path-block./block8=9004,9005\n" +
                  "quarkus.kc-routing.path-block./block9/subpath=9004,9005\n" +
                  "quarkus.kc-routing.path-block./block10=9005\n"),
                  "application.properties"));
  @Test
  public void testStraight() {
    given()
      .when()
      .get("http://localhost:9006/block1")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  // Don't append slash in application-properties as it hangs system if browser does not append
  @Test
  public void testWithSlash() {
    given()
      .when()
      .get("http://localhost:9006/block2/")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithSubpath() {
    given()
      .when()
      .get("http://localhost:9006/block3/subpath")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPorts() {
    given()
      .when()
      .get("http://localhost:9006/block4")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsSwapped() {
    given()
      .when()
      .get("http://localhost:9006/block5")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsAndSlash() {
    given()
      .when()
      .get("http://localhost:9006/block6/")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testWithMultiPortsAndSubpath() {
    given()
      .when()
      .get("http://localhost:9006/block7/subpath")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  // Below tests should all pass through without being blocked
  @Test
  public void testNonSubPath() {
    given()
      .when()
      .get("http://localhost:9006/block1/shouldNotBlock")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testWrongCase() {
    given()
      .when()
      .get("http://localhost:9006/Block1")
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
      .get("http://localhost:9006/block8")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testSubpathMultiPortsNonPortMatch() {
    given()
      .when()
      .get("http://localhost:9006/block9/subpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testNonPortMatch() {
    given()
      .when()
      .get("http://localhost:9006/block10")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
}
