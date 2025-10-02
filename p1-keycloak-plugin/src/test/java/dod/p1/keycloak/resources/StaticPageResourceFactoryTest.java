package dod.p1.keycloak.resources;

import dod.p1.keycloak.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link StaticPageResourceFactory}.
 */
class StaticPageResourceFactoryTest {

    private StaticPageResourceFactory subjectUnderTest;
    private KeycloakSession mockSession;

    @BeforeEach
    void setup() throws Exception {
        Utils.setupFileMocks();
        subjectUnderTest = new StaticPageResourceFactory();
        mockSession = mock(KeycloakSession.class);
    }

    @Test
    void testGetId() {
        assertEquals("onboarding", subjectUnderTest.getId());
    }

    @Test
    void testCreate() {
        RealmResourceProvider provider = subjectUnderTest.create(mockSession);
        
        assertNotNull(provider);
        assertEquals(StaticPageResource.class, provider.getClass());
    }

    @Test
    void testLifecycleMethods() {
        // These methods don't do anything substantive in the implementation,
        // but we should test them for coverage and to ensure they don't throw exceptions
        
        // No assertions needed, just verify they don't throw exceptions
        subjectUnderTest.init(null);
        subjectUnderTest.postInit(null);
        subjectUnderTest.close();
    }
}