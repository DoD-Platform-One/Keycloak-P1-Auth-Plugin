package dod.p1.keycloak.registration;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link CertificateParsingException} class.
 */
public class CertificateParsingExceptionTest {

    private static final String TEST_MESSAGE = "Test error message";
    private static final Throwable TEST_CAUSE = new RuntimeException("Test cause");

    /**
     * Test the constructor that takes only a message.
     */
    @Test
    public void testConstructorWithMessage() {
        CertificateParsingException exception = new CertificateParsingException(TEST_MESSAGE);
        
        assertEquals(TEST_MESSAGE, exception.getMessage(), "The message should be set correctly");
        assertNull(exception.getCause(), "The cause should be null");
    }

    /**
     * Test the constructor that takes a message and a cause.
     */
    @Test
    public void testConstructorWithMessageAndCause() {
        CertificateParsingException exception = new CertificateParsingException(TEST_MESSAGE, TEST_CAUSE);
        
        assertEquals(TEST_MESSAGE, exception.getMessage(), "The message should be set correctly");
        assertEquals(TEST_CAUSE, exception.getCause(), "The cause should be set correctly");
    }

    /**
     * Test that the exception can be thrown and caught.
     */
    @Test
    public void testThrowAndCatch() {
        try {
            throw new CertificateParsingException(TEST_MESSAGE);
        } catch (CertificateParsingException e) {
            assertEquals(TEST_MESSAGE, e.getMessage(), "The message should be preserved when thrown and caught");
        }
    }

    /**
     * Test that the exception with a cause can be thrown and caught.
     */
    @Test
    public void testThrowAndCatchWithCause() {
        try {
            throw new CertificateParsingException(TEST_MESSAGE, TEST_CAUSE);
        } catch (CertificateParsingException e) {
            assertEquals(TEST_MESSAGE, e.getMessage(), "The message should be preserved when thrown and caught");
            assertEquals(TEST_CAUSE, e.getCause(), "The cause should be preserved when thrown and caught");
        }
    }

    /**
     * Test that the exception is a subclass of Exception.
     */
    @Test
    public void testIsSubclassOfException() {
        CertificateParsingException exception = new CertificateParsingException(TEST_MESSAGE);
        assertTrue(exception instanceof Exception, "CertificateParsingException should be a subclass of Exception");
    }
}