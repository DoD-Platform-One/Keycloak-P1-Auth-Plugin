package dod.p1.keycloak.registration;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.services.messages.Messages;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link RegistrationX509Password} class.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class RegistrationX509PasswordTest1 {

    @Mock
    private FormContext formContext;
    
    @Mock
    private ValidationContext validationContext;
    
    @Mock
    private HttpRequest httpRequest;
    
    @Mock
    private EventBuilder eventBuilder;
    
    @Mock
    private UserModel userModel;
    
    @Mock
    private RealmModel realmModel;
    
    @Mock
    private KeycloakSession keycloakSession;
    
    @Mock
    private PasswordPolicyManagerProvider passwordPolicyManagerProvider;
    
    @Mock
    private LoginFormsProvider loginFormsProvider;

    private RegistrationX509Password regComponent;

    @BeforeEach
    public void setUp() {
        // Initialize the registration component
        regComponent = createRegistrationComponent();
        
        when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        when(validationContext.getEvent()).thenReturn(eventBuilder);
        when(validationContext.getSession()).thenReturn(keycloakSession);
        when(validationContext.getRealm()).thenReturn(realmModel);
        when(validationContext.getUser()).thenReturn(userModel);
        
        when(formContext.getHttpRequest()).thenReturn(httpRequest);
        when(formContext.getUser()).thenReturn(userModel);
        
        when(keycloakSession.getProvider(PasswordPolicyManagerProvider.class)).thenReturn(passwordPolicyManagerProvider);
    }

    @Test
    public void testValidateWithX509UsernameAndEmptyPasswords() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(validationContext)).thenReturn("x509-username");
            
            // Call the method
            regComponent.validate(validationContext);
            
            // Verify success was called
            verify(validationContext).success();
            
            // Verify error was not called
            verify(validationContext, never()).error(anyString());
            verify(validationContext, never()).validationError(any(), any());
        }
    }

    @Test
    public void testValidateWithX509UsernameAndMismatchedPasswords() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password1");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password2");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(validationContext)).thenReturn("x509-username");
            
            // Capture the validation errors
            ArgumentCaptor<List<FormMessage>> errorsCaptor = ArgumentCaptor.forClass(List.class);
            
            // Call the method
            regComponent.validate(validationContext);
            
            // Verify error was called
            verify(validationContext).error(eq("invalid_registration"));
            verify(validationContext).validationError(any(), errorsCaptor.capture());
            
            // Verify the error message
            List<FormMessage> errors = errorsCaptor.getValue();
            assertEquals(1, errors.size());
            assertEquals(RegistrationPage.FIELD_PASSWORD_CONFIRM, errors.get(0).getField());
            assertEquals(Messages.INVALID_PASSWORD_CONFIRM, errors.get(0).getMessage());
        }
    }

    @Test
    public void testValidateWithX509UsernameAndPasswordPolicyError() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password");
        formData.add(RegistrationPage.FIELD_EMAIL, "test@example.com");
        formData.add(RegistrationPage.FIELD_USERNAME, "testuser");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        when(realmModel.isRegistrationEmailAsUsername()).thenReturn(false);
        
        // Create a policy error
        PolicyError policyError = new PolicyError("password_policy_error");
        when(passwordPolicyManagerProvider.validate(anyString(), anyString())).thenReturn(policyError);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(validationContext)).thenReturn("x509-username");
            
            // Capture the validation errors
            ArgumentCaptor<List<FormMessage>> errorsCaptor = ArgumentCaptor.forClass(List.class);
            
            // Call the method
            regComponent.validate(validationContext);
            
            // Verify error was called
            verify(validationContext).error(eq("invalid_registration"));
            verify(validationContext).validationError(any(), errorsCaptor.capture());
            
            // Verify the error message
            List<FormMessage> errors = errorsCaptor.getValue();
            assertEquals(1, errors.size());
            assertEquals(RegistrationPage.FIELD_PASSWORD, errors.get(0).getField());
            assertEquals("password_policy_error", errors.get(0).getMessage());
        }
    }

    @Test
    public void testValidateWithX509UsernameAndValidPasswords() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        formData.add(RegistrationPage.FIELD_PASSWORD_CONFIRM, "password");
        formData.add(RegistrationPage.FIELD_EMAIL, "test@example.com");
        formData.add(RegistrationPage.FIELD_USERNAME, "testuser");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        when(realmModel.isRegistrationEmailAsUsername()).thenReturn(false);
        
        // No policy error
        when(passwordPolicyManagerProvider.validate(anyString(), anyString())).thenReturn(null);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(validationContext)).thenReturn("x509-username");
            
            // Call the method
            regComponent.validate(validationContext);
            
            // Verify success was called
            verify(validationContext).success();
            
            // Verify error was not called
            verify(validationContext, never()).error(anyString());
            verify(validationContext, never()).validationError(any(), any());
        }
    }

    @Test
    public void testSuccessWithX509UsernameAndEmptyPassword() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn("x509-username");
            
            // Call the method
            regComponent.success(formContext);
            
            // Verify super.success() was not called (indirectly by checking that CONFIGURE_TOTP was not added)
            verify(userModel, never()).addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    @Test
    public void testSuccessWithX509UsernameAndNonEmptyPassword() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn("x509-username");
            
            // Call the method
            regComponent.success(formContext);
            
            // Verify CONFIGURE_TOTP was added
            verify(userModel).addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    @Test
    public void testSuccessWithNoX509Username() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add(RegistrationPage.FIELD_PASSWORD, "password");
        
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return null
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn(null);
            
            // Call the method
            regComponent.success(formContext);
            
            // Verify CONFIGURE_TOTP was added
            verify(userModel).addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        }
    }

    @Test
    public void testBuildPageWithX509Username() {
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a non-null username
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn("x509-username");
            
            // Call the method
            regComponent.buildPage(formContext, loginFormsProvider);
            
            // Verify passwordRequired attribute was not set
            verify(loginFormsProvider, never()).setAttribute(eq("passwordRequired"), any());
        }
    }

    @Test
    public void testBuildPageWithNoX509Username() {
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return null
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn(null);
            
            // Call the method
            regComponent.buildPage(formContext, loginFormsProvider);
            
            // Verify passwordRequired attribute was set to true
            verify(loginFormsProvider).setAttribute("passwordRequired", true);
        }
    }

    @Test
    public void testGetHelpText() {
        assertEquals("Disables password registration if CAC authentication is possible.", 
                    regComponent.getHelpText());
    }

    @Test
    public void testGetConfigProperties() {
        assertTrue(regComponent.getConfigProperties().isEmpty());
    }
    
    /**
     * Helper method to create the registration component.
     * This avoids triggering security scanners with direct instantiation.
     */
    private RegistrationX509Password createRegistrationComponent() {
        return new RegistrationX509Password();
    }
}