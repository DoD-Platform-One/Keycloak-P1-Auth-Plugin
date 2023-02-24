package dod.p1.kc.routing.deployment.redirects;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.hamcrest.Matchers.containsString;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import static io.restassured.RestAssured.given;

public class SimpleRedirectFalseTest {

  // @RegisterExtension
  // static final QuarkusUnitTest config = new QuarkusUnitTest();

  @RegisterExtension
  static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
          .addAsResource(new StringAsset(
                  "quarkus.kc-routing.path-redirect./DontFollow1=/ArbitraryValue\n" +
                  "quarkus.kc-routing.path-redirect./DontFollow2=/ArbitraryValue\n"),
                  "application.properties"));
  @Test
  public void testOne() {
    given()
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/DontFollow1")
      .then().statusCode(302);
  }

  @Test
  public void testTwo() {
    given()
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/DontFollow2")
      .then().statusCode(302);
  }

  public void testWrongCase() {
    given()
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/dontFollow1")
      .then().statusCode(404);
  }


  @Test
  public void testNonRoute() {
    given()
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/NonRoute")
      .then().statusCode(404);
  }

}
