package dod.p1.kc.routing.deployment.pathprefixes;

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

public class PathPrefixThroughTest {

  // @RegisterExtension
  // static final QuarkusUnitTest config = new QuarkusUnitTest();

  @RegisterExtension
  static final QuarkusUnitTest config = new QuarkusUnitTest().withApplicationRoot((jar) -> jar
          .addAsResource(new StringAsset(
                  "quarkus.kc-routing.path-prefix./first/second=/newfirst/newsecond\n" +
                  "quarkus.kc-routing.path-prefix./path1/path2=/replacement\n"),
                  "application.properties"));

  @Test
  public void testOnetoOne() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/first/second?testvarA=A&testvarB=B")
      .then().statusCode(302)
      .header("Location", is("/newfirst/newsecond?testvar1=1&testvar2=2&testvarA=A&testvarB=B"));

  }

  @Test
  public void testPrePathOnly() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/first/second/third?testvarA=A&testvarB=B")
      .then().statusCode(302)
      .header("Location", is("/newfirst/newsecond/third?testvar1=1&testvar2=2&testvarA=A&testvarB=B"));

  }

  @Test
  public void testPathNotFound() {
    given()
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/some/bad/path?testvarA=A&testvarB=B")
      .then().statusCode(404);

  }

  @Test
  public void testIncorrectParameters() {
    given()
      .queryParam("testvar1", "1")
      .queryParam("testvar2", "2")
      .when()
      .redirects().follow(false)
      .get("http://localhost:9006/path1/path2/anything_else?testvarA=A&testvarB=B")
      .then().statusCode(302)
      .header("Location", not("/?something=wrong"));

  }
}
