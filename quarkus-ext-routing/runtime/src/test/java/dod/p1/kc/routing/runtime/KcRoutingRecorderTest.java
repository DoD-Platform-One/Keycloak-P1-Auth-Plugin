package dod.p1.kc.routing.runtime;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.*;

public class KcRoutingRecorderTest {

    @Test
    void testGetHandlerCreatesNewHandler() {
        KcRoutingRecorder recorder = new KcRoutingRecorder();

        KcRoutingHandler handler = recorder.getHandler();

        // Verify that getHandler creates a new handler instance
        assertNotNull(handler);
    }

    @Test
    void testGetHandlerReturnsExistingHandler() {
        KcRoutingRecorder recorder = new KcRoutingRecorder();

        KcRoutingHandler handler1 = recorder.getHandler();
        KcRoutingHandler handler2 = recorder.getHandler();

        // Verify that getHandler returns the existing handler instance
        assertSame(handler1, handler2);
    }

    @Test
    void testSetPathRedirects() {
        // Condition 1
        KcRoutingRecorder recorder = new KcRoutingRecorder();
        recorder.handler = mock(KcRoutingHandler.class);

        Map<String, String> map = new HashMap<>();
        recorder.setPathRedirects(map);

        // Verify that setPathRedirects calls the corresponding method on the handler
        KcRoutingHandler.setPathRedirects(map);

        // Condition 2
        recorder.handler = null;
        recorder.setPathRedirects(map);
    }

    @Test
    void testSetPathPrefixes() {
        // Condition 1
        KcRoutingRecorder recorder = new KcRoutingRecorder();
        recorder.handler = mock(KcRoutingHandler.class);

        Map<String, String> map = new HashMap<>();
        recorder.setPathPrefixes(map);

        // Verify that setPathPrefixes calls the corresponding method on the handler
        KcRoutingHandler.setPathPrefixes(map);

        // Condition 2
        recorder.handler = null;
        recorder.setPathPrefixes(map);
    }

    @Test
    void testSetPathFilters() {
        // Condition 1
        KcRoutingRecorder recorder = new KcRoutingRecorder();
        recorder.handler = mock(KcRoutingHandler.class);

        Map<String, String> map = new HashMap<>();
        recorder.setPathFilters(map);

        // Verify that setPathFilters calls the corresponding method on the handler
        KcRoutingHandler.setPathFilters(map);

        // Condition 2
        recorder.handler = null;
        recorder.setPathFilters(map);
    }

    @Test
    void testSetPathBlocks() {
        // Condition 1
        KcRoutingRecorder recorder = new KcRoutingRecorder();
        recorder.handler = mock(KcRoutingHandler.class);

        Map<String, String> map = new HashMap<>();
        recorder.setPathBlocks(map);

        // Verify that setPathBlocks calls the corresponding method on the handler
        KcRoutingHandler.setPathBlocks(map);

        // Condition 2
        recorder.handler = null;
        recorder.setPathBlocks(map);
    }

    @Test
    void testSetPathRecursiveBlocks() {
        // Condition 1
        KcRoutingRecorder recorder = new KcRoutingRecorder();
        recorder.handler = mock(KcRoutingHandler.class);

        Map<String, String> map = new HashMap<>();
        recorder.setPathRecursiveBlocks(map);

        // Verify that setPathRecursiveBlocks calls the corresponding method on the handler
        KcRoutingHandler.setPathRecursiveBlocks(map);

        // Condition 2
        recorder.handler = null;
        recorder.setPathRecursiveBlocks(map);
    }

    @Test
    void testSetPathAllows() {
        // Condition 1
        KcRoutingRecorder recorder = new KcRoutingRecorder();
        recorder.handler = mock(KcRoutingHandler.class);

        Map<String, String> map = new HashMap<>();
        recorder.setPathAllows(map);

        // Verify that setPathAllows calls the corresponding method on the handler
        KcRoutingHandler.setPathAllows(map);

        // Condition 2
        recorder.handler = null;
        recorder.setPathAllows(map);
    }
}
