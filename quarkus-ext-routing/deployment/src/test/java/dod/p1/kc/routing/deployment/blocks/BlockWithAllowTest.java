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

public class BlockWithAllowTest {

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
                  "quarkus.kc-routing.path-allow./block1=127.0.0.1\n" +

                  "quarkus.kc-routing.path-block./block2/=9006\n" +
                  "quarkus.kc-routing.path-allow./block2/=127.0.0.1\n" +

                  "quarkus.kc-routing.path-block./block3/subpath=9006\n" +
                  "quarkus.kc-routing.path-allow./block3/subpath=127.0.0.1\n" +
                  //loopback IP should allow
                  "quarkus.kc-routing.path-block./block4=9006,9005\n" +
                  "quarkus.kc-routing.path-allow./block4=127.0.0.1\n" +
                  //;pp[bacl CIDR should allow
                  "quarkus.kc-routing.path-block./block5=9005,9006\n" +
                  "quarkus.kc-routing.path-allow./block5=127.0.0.0/23\n" +
                  //Host names aren't supported, should block
                  "quarkus.kc-routing.path-block./block6/subpath=9006,9005\n" +
                  "quarkus.kc-routing.path-allow./block6=localhost\n" +
                  //Wrong IP, should block
                  "quarkus.kc-routing.path-block./block7=9006,9005\n" +
                  "quarkus.kc-routing.path-allow./block7=127.0.1.0/24\n" +
                  //Wrong Port, should route
                  "quarkus.kc-routing.path-block./block8=9005,9004\n" +
                  "quarkus.kc-routing.path-allow./block8=127.0.0.0/24\n"),
                  "application.properties"));
  @Test
  public void testBlockWithAllow() {
    given()
      .when()
      .get("http://localhost:9006/block1")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  // Don't append slash in application-properties as it hangs system if browser does not append
  @Test
  public void testBlockWithAllowSlash() {
    given()
      .when()
      .get("http://localhost:9006/block2/")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowSubpath() {
    given()
      .when()
      .get("http://localhost:9006/block3/subpath")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowMultiPorts() {
    given()
      .when()
      .get("http://localhost:9006/block4")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingCIRD() {
    given()
      .when()
      .get("http://localhost:9006/block5")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingHostname() {
    given()
      .when()
      .get("http://localhost:9006/block6/subpath")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingWrongCIDR() {
    given()
      .when()
      .get("http://localhost:9006/block7")
      .then().statusCode(HTTP_BAD_REQUEST)
      .body(is("<html><body><h1>Resource Blocked</h1></body></html>"));
  }
  @Test
  public void testBlockWithAllowUsingWrongPort() {
    given()
      .when()
      .get("http://localhost:9006/block8")
      .then().statusCode(HTTP_NOT_FOUND)
      .body(is("<html><body><h1>Resource not found</h1></body></html>"));
  }
}
