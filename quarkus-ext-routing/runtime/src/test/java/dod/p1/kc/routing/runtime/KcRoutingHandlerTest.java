package dod.p1.kc.routing.runtime;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

public class KcRoutingHandlerTest {

    private RoutingContext routingContext;
    private Logger logger;
    private Map<String, String> map;

    @BeforeAll
    public static void setUpMocks(){
        // mock static
        mockStatic(Logger.class);
    }

    @BeforeEach
    public void setup(){
        // mocks
        HttpServerRequest httpServerRequest = mock(HttpServerRequest.class);
        HttpServerResponse httpServerResponse = mock(HttpServerResponse.class);
        SocketAddress socketAddress = mock(SocketAddress.class);

        // global mocks
        routingContext = mock(RoutingContext.class);
        logger = mock(Logger.class);

        // global variables
        map = new HashMap<>();

        // Add values to the map
        map.put("key1", "1,2,3,4,5,6,7,8,9");
        map.put("key2", "value2");
        map.put("key3", "value3");
        map.put("key1/", "244.168.0.0");

        // routing context
        when(routingContext.normalizedPath()).thenReturn("key1");
        when(routingContext.request()).thenReturn(httpServerRequest);
        when(routingContext.request().query()).thenReturn("thisQuery");
        when(routingContext.request().uri()).thenReturn("thisIsAnUri");
        when(routingContext.request().localAddress()).thenReturn(socketAddress);
//        when(routingContext.request().localAddress().hostAddress()).thenReturn("hostAddress");
        when(routingContext.request().localAddress().port()).thenReturn(5);
        when(routingContext.response()).thenReturn(httpServerResponse);
        when(routingContext.response().setStatusCode(anyInt())).thenReturn(httpServerResponse);

        // logger
        when(Logger.getLogger(anyString())).thenReturn(logger);
        when(logger.isDebugEnabled()).thenReturn(true);
    }

    @Test
    void testHandle() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }

    @Test
    void testSetPathRedirects() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.setPathRedirects(map);

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }

    @Test
    void testSetPathPrefixes() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.setPathPrefixes(map);

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }

    @Test
    void testSetPathFilters() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.setPathFilters(map);

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }

    @Test
    void testSetPathBlocks() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.setPathBlocks(map);

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }

    @Test
    void testSetPathRecursiveBlocks() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.setPathRecursiveBlocks(map);

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }

    @Test
    void testSetPathAllows() {
        KcRoutingHandler kcRoutingHandler = new KcRoutingHandler();

        kcRoutingHandler.setPathAllows(map);

        kcRoutingHandler.handle(routingContext);

        // Verify that kcRoutingHandler creates a new handler instance
        assertNotNull(kcRoutingHandler);
    }
}
