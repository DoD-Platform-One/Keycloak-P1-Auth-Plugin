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

public class RecursiveBlockWithAllowTest {

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
                  "quarkus.kc-routing.path-allow./recursiveblock1=127.0.0.1\n" +

                  "quarkus.kc-routing.path-recursive-block./recursiveblock2/=9006\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock2/=127.0.0.1\n" +

                  "quarkus.kc-routing.path-recursive-block./recursiveblock3/subpath=9006\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock3/subpath=127.0.0.1\n" +
                  //loopback IP should allow
                  "quarkus.kc-routing.path-recursive-block./recursiveblock4=9006,9005\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock4=127.0.0.1\n" +
                  //CIDR should allow
                  "quarkus.kc-routing.path-recursive-block./recursiveblock5=9005,9006\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock5=127.0.0.0/23\n" +
                  //Should Allow due to allow to localhost
                  "quarkus.kc-routing.path-recursive-block./recursiveblock6/=9006,9005\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock6/=localhost\n" +
                  //Should allow due to allow at root level
                  "quarkus.kc-routing.path-recursive-block./recursiveblock6/subpath=9006,9005\n" +
                  //Wrong IP, should block
                  "quarkus.kc-routing.path-recursive-block./recursiveblock7=9006,9005\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock7=127.0.1.0/24\n" +
                  //Wrong Port, should route
                  "quarkus.kc-routing.path-recursive-block./recursiveblock8=9005,9004\n" +
                  "quarkus.kc-routing.path-allow./recursiveblock8=127.0.0.0/24\n"),
                  "application.properties"));
  @Test
  public void testBlockWithAllow() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock1")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  // Don't append slash in application-properties as it hangs system if browser does not append
  @Test
  public void testBlockWithAllowSlash() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock2/")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowSubpath() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock3/subpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowMultiPorts() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock4")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingCIRD() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock5")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  //should work due to allow
  @Test
  public void testBlockRootWithAllowOnSubUsingHostname() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock6")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  //should work due to allow at root level
  @Test
  public void testBlockWithAllowUsingHostname() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock6/subpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingWrongCIDR() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock7")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingWrongPort() {
    given()
      .when()
      .get("http://localhost:9006/recursiveblock8")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
}
