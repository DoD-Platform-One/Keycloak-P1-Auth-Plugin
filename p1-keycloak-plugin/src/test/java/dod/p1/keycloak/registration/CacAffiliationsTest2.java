package dod.p1.keycloak.registration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Additional test coverage for {@link CacAffiliations} class.
 */
public class CacAffiliationsTest2 {

    @ParameterizedTest
    @ValueSource(strings = {"USAF", "USAFR", "USANG", "USARMY", "USARMYR", "USARMYNG",
                           "USCG", "USCGR", "USMC", "USMCR", "USNAVY", "USNAVYR",
                           "USSF", "DoD", "U.S. Government", "AAS", "CONTRACTOR", "FFRDC", "OTHER"})
    public void testGetLongNameWithValidShortNames(String shortName) {
        // Test that all valid short names return a non-null long name
        assertNotNull(CacAffiliations.getLongName(shortName));
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "123", "Unknown"})
    public void testGetLongNameWithInvalidShortNames(String shortName) {
        // Test that invalid short names return null
        assertNull(CacAffiliations.getLongName(shortName));
    }

    @Test
    public void testGetLongNameWithNullShortName() {
        // Test with null shortName
        try {
            CacAffiliations.getLongName(null);
            fail("Expected NullPointerException");
        } catch (NullPointerException e) {
            // Expected
        }
    }

    @Test
    public void testGetLongNameWithEmptyShortName() {
        // Test with empty shortName
        assertNull(CacAffiliations.getLongName(""));
    }

    @ParameterizedTest
    @ValueSource(strings = {"US Air Force", "US Air Force Reserve", "US Air National Guard",
                           "US Army", "US Army Reserve", "US Army National Guard",
                           "US Coast Guard", "US Coast Guard Reserve", "US Marine Corps",
                           "US Marine Corps Reserve", "US Navy", "US Navy Reserve",
                           "US Space Force", "Dept of Defense", "Federal Government",
                           "A&AS", "Contractor", "FFRDC", "Other"})
    public void testGetShortNameWithValidLongNames(String longName) {
        // Test that all valid long names return a non-null short name
        assertNotNull(CacAffiliations.getShortName(longName));
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "123", "Unknown"})
    public void testGetShortNameWithInvalidLongNames(String longName) {
        // Test that invalid long names return null
        assertNull(CacAffiliations.getShortName(longName));
    }

    @Test
    public void testGetShortNameWithNullLongName() {
        // Test with null longName
        try {
            CacAffiliations.getShortName(null);
            fail("Expected NullPointerException");
        } catch (NullPointerException e) {
            // Expected
        }
    }

    @Test
    public void testGetShortNameWithEmptyLongName() {
        // Test with empty longName
        assertNull(CacAffiliations.getShortName(""));
    }

    @Test
    public void testBidirectionalTranslation() {
        // Test that translating from short to long and back returns the original short name
        String shortName = "USAF";
        String longName = CacAffiliations.getLongName(shortName);
        assertEquals(shortName, CacAffiliations.getShortName(longName));

        // Test another example
        shortName = "CONTRACTOR";
        longName = CacAffiliations.getLongName(shortName);
        assertEquals(shortName, CacAffiliations.getShortName(longName));
    }

    @Test
    public void testCaseInsensitivity() {
        // Test that the translation is case-sensitive (it should be)
        assertNotEquals(CacAffiliations.getLongName("usaf"), CacAffiliations.getLongName("USAF"));
        assertNotEquals(CacAffiliations.getShortName("us air force"), CacAffiliations.getShortName("US Air Force"));
    }
}
