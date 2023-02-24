package dod.p1.kc.routing.deployment.config;

import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;

public class KcRoutingEmptyConfigTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withConfigurationResource("test-empty.properties")
            .withEmptyApplication();
    @Test
    public void testEmptyConfig() {
      RestAssured.when().get("http://localhost:9006/").then().statusCode(404);

    }

}
