package dod.p1.keycloak.registration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.FormContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.validation.Validation;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.common.YAMLConfigEmailAutoJoin;
import javax.security.auth.x500.X500Principal;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT) // Use lenient strictness to avoid unnecessary stubbing errors
public class RegistrationValidationTest1 {

    @Mock
    private FormContext formContext;

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    @Mock
    private HttpRequest httpRequest;

    private RegistrationValidation registrationValidation;

    @BeforeEach
    public void setUp() {
        registrationValidation = new RegistrationValidation();
        when(formContext.getHttpRequest()).thenReturn(httpRequest);
    }

    /**
     * Helper method to invoke a private method using reflection.
     */
    private <T> T invokePrivateMethod(Object instance, String methodName, Class<?>[] paramTypes, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return (T) method.invoke(instance, args);
    }

    @Test
    public void testBindRequiredActions_WithX509Username() throws Exception {
        // Test with X509 username present
        String x509Username = "x509-username@mil";

        invokePrivateMethod(registrationValidation, "bindRequiredActions",
                new Class<?>[] { UserModel.class, String.class }, user, x509Username);

        // Verify required actions
        verify(user).addRequiredAction("TERMS_AND_CONDITIONS");
        verify(user).addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
        verify(user, never()).addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        verify(user, never()).setEmailVerified(true);
    }

    @Test
    public void testBindRequiredActions_WithoutX509Username() throws Exception {
        // Test without X509 username
        invokePrivateMethod(registrationValidation, "bindRequiredActions",
                new Class<?>[] { UserModel.class, String.class }, user, null);

        // Verify required actions
        verify(user).addRequiredAction("TERMS_AND_CONDITIONS");
        verify(user).addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
        verify(user).addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        verify(user, never()).setEmailVerified(true);
    }

    @Test
    public void testProcessX509UserAttribute_WithX509Username() throws Exception {
        // Test with X509 username present
        String x509Username = "x509-username@mil";

        try (MockedStatic<CommonConfig> configMock = Mockito.mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            configMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(realm)).thenReturn("usercertificate");

            invokePrivateMethod(registrationValidation, "processX509UserAttribute",
                    new Class<?>[] { KeycloakSession.class, RealmModel.class, UserModel.class, String.class },
                    session, realm, user, x509Username);

            // Verify attribute was set
            verify(user).setSingleAttribute("usercertificate", x509Username);
        }
    }

    @Test
    public void testProcessX509UserAttribute_WithoutX509Username() throws Exception {
        // Test without X509 username
        invokePrivateMethod(registrationValidation, "processX509UserAttribute",
                new Class<?>[] { KeycloakSession.class, RealmModel.class, UserModel.class, String.class },
                session, realm, user, null);

        // Verify attribute was not set
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testGenerateUniqueStringIdForMattermost() throws Exception {
        // Setup form data
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_EMAIL, "test@example.com");

        invokePrivateMethod(registrationValidation, "generateUniqueStringIdForMattermost",
                new Class<?>[] { MultivaluedMap.class, UserModel.class }, formData, user);

        // Verify attribute was set (we can't check the exact value as it includes a timestamp)
        verify(user).setSingleAttribute(eq("mattermostid"), anyString());
    }

    @Test
    public void testJoinValidUserToGroups_WithX509Username() throws Exception {
        // Setup
        String x509Username = "x509-username@mil";
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.getUsername()).thenReturn("testuser");
        when(formContext.getUser()).thenReturn(user);
        when(formContext.getSession()).thenReturn(session);
        when(formContext.getRealm()).thenReturn(realm);

        // Mock groups
        GroupModel group1 = mock(GroupModel.class);
        when(group1.getName()).thenReturn("x509-group");

        try (MockedStatic<CommonConfig> configMock = Mockito.mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            configMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            // Use Stream.of() instead of List.of() since the method returns Stream<GroupModel>
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group1));

            invokePrivateMethod(registrationValidation, "joinValidUserToGroups",
                    new Class<?>[] { FormContext.class, UserModel.class, String.class },
                    formContext, user, x509Username);

            // Verify user joined the group
            verify(user).joinGroup(group1);
            verify(user, never()).setSingleAttribute("public-registrant", "true");
        }
    }

    @Test
    public void testJoinValidUserToGroups_WithEmailMatch() throws Exception {
        // Setup
        when(user.getEmail()).thenReturn("test@example.mil");
        when(user.getUsername()).thenReturn("testuser");
        when(formContext.getUser()).thenReturn(user);
        when(formContext.getSession()).thenReturn(session);
        when(formContext.getRealm()).thenReturn(realm);

        // Mock groups
        GroupModel group1 = mock(GroupModel.class);
        when(group1.getName()).thenReturn("mil-group");

        // Mock email match configuration
        YAMLConfigEmailAutoJoin emailMatch = mock(YAMLConfigEmailAutoJoin.class);
        when(emailMatch.getDomains()).thenReturn(List.of(".mil"));
        when(emailMatch.getGroups()).thenReturn(List.of("/mil-group"));
        when(emailMatch.getGroupModels()).thenReturn(List.of(group1));

        try (MockedStatic<CommonConfig> configMock = Mockito.mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            configMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);

            // Create a new stream for each call to avoid "stream has already been operated upon or closed"
            when(commonConfig.getEmailMatchAutoJoinGroup()).thenAnswer(invocation -> Stream.of(emailMatch));

            invokePrivateMethod(registrationValidation, "joinValidUserToGroups",
                    new Class<?>[] { FormContext.class, UserModel.class, String.class },
                    formContext, user, null);

            // Verify user joined the group
            verify(user).joinGroup(group1);
            verify(user, never()).setSingleAttribute("public-registrant", "true");
        }
    }

    @Test
    public void testJoinValidUserToGroups_WithoutEmailMatch() throws Exception {
        // Setup
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.getUsername()).thenReturn("testuser");
        when(formContext.getUser()).thenReturn(user);
        when(formContext.getSession()).thenReturn(session);
        when(formContext.getRealm()).thenReturn(realm);

        // Mock groups
        GroupModel group1 = mock(GroupModel.class);
        when(group1.getName()).thenReturn("public-group");

        // Mock email match configuration
        YAMLConfigEmailAutoJoin emailMatch = mock(YAMLConfigEmailAutoJoin.class);
        when(emailMatch.getDomains()).thenReturn(List.of(".mil", ".gov"));

        try (MockedStatic<CommonConfig> configMock = Mockito.mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            configMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);

            // Create a new stream for each call to avoid "stream has already been operated upon or closed"
            when(commonConfig.getEmailMatchAutoJoinGroup()).thenAnswer(invocation -> Stream.of(emailMatch));
            when(commonConfig.getNoEmailMatchAutoJoinGroup()).thenReturn(Stream.of(group1));

            invokePrivateMethod(registrationValidation, "joinValidUserToGroups",
                    new Class<?>[] { FormContext.class, UserModel.class, String.class },
                    formContext, user, null);

            // Verify user joined the public group and got the public-registrant attribute
            verify(user).joinGroup(group1);
            verify(user).setSingleAttribute("public-registrant", "true");
        }
    }

    @Test
    public void testBuildFormFromX509_WithValidCertificate() throws Exception {
        // Setup
        X509Certificate cert = mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=DOE.JOHN.1234567890,OU=USAF,O=U.S. Government,C=US");
        when(cert.getSubjectX500Principal()).thenReturn(principal);

        X509Certificate[] certs = new X509Certificate[] { cert };

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class)) {
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(FormContext.class))).thenReturn("1234567890@mil");
            x509ToolsMock.when(() -> X509Tools.translateAffiliationShortName("USAF")).thenReturn("Air Force");

            MultivaluedMap<String, String> result = invokePrivateMethod(registrationValidation, "buildFormFromX509",
                    new Class<?>[] { FormContext.class, X509Certificate[].class },
                    formContext, certs);

            // Verify form data was populated correctly
            assertEquals("1234567890@mil", result.getFirst("cacIdentity"));
            assertEquals("John", result.getFirst("firstName"));
            assertEquals("Doe", result.getFirst("lastName"));
            assertEquals("Air Force", result.getFirst("user.attributes.affiliation"));
        }
    }

    @Test
    public void testBuildFormFromX509_WithInvalidCertificate() throws Exception {
        // Setup with invalid certificate format
        X509Certificate cert = mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=Invalid Format,OU=USAF,O=U.S. Government,C=US");
        when(cert.getSubjectX500Principal()).thenReturn(principal);

        X509Certificate[] certs = new X509Certificate[] { cert };

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle("cacIdentity", "1234567890@mil"); // Pre-populate the form data
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class)) {
            // Use any() matcher to ensure this mock works regardless of the argument
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(FormContext.class))).thenReturn("1234567890@mil");

            MultivaluedMap<String, String> result = invokePrivateMethod(registrationValidation, "buildFormFromX509",
                    new Class<?>[] { FormContext.class, X509Certificate[].class },
                    formContext, certs);

            // Verify only cacIdentity was set, but not the other fields due to parsing error
            assertEquals("1234567890@mil", result.getFirst("cacIdentity"));
            assertNull(result.getFirst("firstName"));
            assertNull(result.getFirst("lastName"));
        }
    }

    @Test
    public void testBuildFormFromX509_WithNoCertificates() throws Exception {
        // Setup with no certificates
        X509Certificate[] certs = new X509Certificate[0];

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = Mockito.mockStatic(X509Tools.class)) {
            // Use any() matcher to ensure this mock works regardless of the argument
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(FormContext.class))).thenReturn("1234567890@mil");

            MultivaluedMap<String, String> result = invokePrivateMethod(registrationValidation, "buildFormFromX509",
                    new Class<?>[] { FormContext.class, X509Certificate[].class },
                    formContext, certs);

            // Verify no form data was populated
            assertNull(result.getFirst("firstName"));
            assertNull(result.getFirst("lastName"));
            assertNull(result.getFirst("user.attributes.affiliation"));
        }
    }
}
