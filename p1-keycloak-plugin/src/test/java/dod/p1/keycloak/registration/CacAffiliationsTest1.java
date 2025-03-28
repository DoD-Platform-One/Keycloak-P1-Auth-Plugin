package dod.p1.keycloak.registration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Additional test coverage for {@link CacAffiliations} class.
 */
public class CacAffiliationsTest1 {

    @Test
    public void testPrivateConstructor() throws Exception {
        // Test that the constructor is private
        Constructor<CacAffiliations> constructor = CacAffiliations.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));

        // Make it accessible and create an instance (for coverage)
        constructor.setAccessible(true);
        try {
            constructor.newInstance();
        } catch (InvocationTargetException e) {
            // We don't expect an exception, but if one occurs, it should not be an InvocationTargetException
            fail("Constructor threw an exception: " + e.getTargetException());
        }
    }

    @ParameterizedTest
    @CsvSource({
        "USAF, US Air Force",
        "USARMY, US Army",
        "USNAVY, US Navy",
        "USMC, US Marine Corps",
        "USCG, US Coast Guard",
        "USSF, US Space Force",
        "DoD, Dept of Defense",
        "CONTRACTOR, Contractor",
        "OTHER, Other"
    })
    public void testBidirectionalTranslationWithSpecificValues(String shortName, String expectedLongName) {
        // Test that the long name matches the expected value
        assertEquals(expectedLongName, CacAffiliations.getLongName(shortName));

        // Test that translating back to short name works
        assertEquals(shortName, CacAffiliations.getShortName(expectedLongName));
    }

    @Test
    public void testMixedCaseInput() {
        // Test with mixed case input (should not match due to case sensitivity)
        assertNull(CacAffiliations.getLongName("UsAf"));
        assertNull(CacAffiliations.getShortName("Us AiR FoRcE"));
    }
}
