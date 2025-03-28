package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.common.YAMLConfigEmailAutoJoin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.FormMessage;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link RegistrationValidation} class.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class RegistrationValidationTest2 {

    // Constants from RegistrationPage
    private static final String FIELD_USERNAME = "username";
    private static final String FIELD_FIRST_NAME = "firstName";
    private static final String FIELD_LAST_NAME = "lastName";
    private static final String FIELD_EMAIL = "email";

    @Mock
    private ValidationContext validationContext;
    
    @Mock
    private FormContext formContext;
    
    @Mock
    private KeycloakSession session;
    
    @Mock
    private RealmModel realm;
    
    @Mock
    private LoginFormsProvider loginFormsProvider;
    
    @Mock
    private CommonConfig commonConfig;
    
    @Mock
    private HttpRequest httpRequest;
    
    @Mock
    private UserProvider userProvider;
    
    private RegistrationValidation registrationValidation;
    
    @BeforeEach
    public void setUp() {
        registrationValidation = new RegistrationValidation();
        
        // Setup common mocks
        when(validationContext.getSession()).thenReturn(session);
        when(validationContext.getRealm()).thenReturn(realm);
        when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        
        when(formContext.getSession()).thenReturn(session);
        when(formContext.getRealm()).thenReturn(realm);
        when(formContext.getHttpRequest()).thenReturn(httpRequest);
        
        // Mock the UserProvider
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserByEmail(any(RealmModel.class), anyString())).thenReturn(null);
        
        // Create an empty form data to avoid NPEs
        MultivaluedMap<String, String> emptyFormData = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(emptyFormData);
    }
    
    @Test
    public void testMattermostUsernameValidation() {
        // Setup
        List<FormMessage> errors = new ArrayList<>();
        
        // Test with invalid username (starts with number)
        registrationValidation.mattermostUsernameValidation(errors, "1username");
        assertEquals(1, errors.size());
        
        // Clear errors
        errors.clear();
        
        // Test with invalid username (contains special characters)
        registrationValidation.mattermostUsernameValidation(errors, "user@name");
        assertEquals(1, errors.size());
        
        // Clear errors
        errors.clear();
        
        // Test with invalid username (too short)
        registrationValidation.mattermostUsernameValidation(errors, "us");
        assertEquals(1, errors.size());
        
        // Clear errors
        errors.clear();
        
        // Test with valid username
        registrationValidation.mattermostUsernameValidation(errors, "username");
        assertEquals(0, errors.size());
    }
    
    @Test
    public void testBuildPageWithNoFormData() {
        // Setup
        when(httpRequest.getDecodedFormParameters()).thenReturn(null);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return null
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn(null);
            
            // Call the method
            registrationValidation.buildPage(formContext, loginFormsProvider);
            
            // Verify
            verify(loginFormsProvider, never()).setAttribute(anyString(), any());
        }
    }
    
    @Test
    public void testBuildPageWithFormData() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add("email", "valid@example.com");
        formData.add("user.attributes.affiliation", "USAF");
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return null
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn(null);
            
            // Call the method
            registrationValidation.buildPage(formContext, loginFormsProvider);
            
            // Verify - no attributes set when X509Username is null
            verify(loginFormsProvider, never()).setAttribute(eq("affiliations"), any());
        }
    }
}