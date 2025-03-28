package org.keycloak.forms.account.freemarker.model;

import jakarta.ws.rs.core.UriBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;
import org.keycloak.authentication.otp.OTPApplicationProvider;

import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Stream;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.mockStatic;

/**
 * Refactored test class for {@link TotpBean} using JUnit 5 and Mockito inline mock maker
 * to replace PowerMock functionality.
 */
class TotpBeanTest {

    @Mock
    private KeycloakSession session;
    @Mock
    private RealmModel realm;
    @Mock
    private UserModel user;
    @Mock
    private UriBuilder uriBuilder;
    @Mock
    private OTPPolicy otpPolicy;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Stub the realm's OTPPolicy so TotpUtils.qrCode() doesn't receive a null.
        when(realm.getOTPPolicy()).thenReturn(otpPolicy);
        // Use the SubjectCredentialManager returned by user.credentialManager()
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credentialManager);
    }

    @Test
    void testTotpBeanEnabled() throws Exception {
        SubjectCredentialManager credentialManager = user.credentialManager();
        when(credentialManager.isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(true);

        CredentialModel credentialModelMock = mock(CredentialModel.class);
        when(credentialModelMock.getType()).thenReturn(CredentialModel.TOTP);
        when(credentialModelMock.getSecretData()).thenReturn("totpSecret");
        // Return a stream with one mocked credential
        when(credentialManager.getStoredCredentialsByTypeStream(any()))
                .thenReturn(Stream.of(credentialModelMock));

        when(realm.getOTPPolicy()).thenReturn(otpPolicy);

        // Prepare a single OTPApplicationProvider that supports the mocked OTPPolicy
        OTPApplicationProvider applicationProvider = mock(OTPApplicationProvider.class);
        when(applicationProvider.supports(otpPolicy)).thenReturn(true);
        when(applicationProvider.getName()).thenReturn("testApplication");

        // Return a set with our one application provider
        when(session.getAllProviders(eq(OTPApplicationProvider.class)))
                .thenReturn(new HashSet<>(List.of(applicationProvider)));

        // Mock URI building
        when(uriBuilder.replaceQueryParam(eq("mode"), any(String.class))).thenReturn(uriBuilder);
        when(uriBuilder.build()).thenReturn(new URI("http://example.com"));

        // Static mocks for HmacOTP and TotpUtils
        try (var hmacOTPMock = mockStatic(org.keycloak.models.utils.HmacOTP.class);
             var totpUtilsMock = mockStatic(TotpUtils.class)) {

            hmacOTPMock.when(() -> org.keycloak.models.utils.HmacOTP.generateSecret(20))
                       .thenReturn("20_Characters_needed");
            totpUtilsMock.when(() -> TotpUtils.encode(anyString())).thenReturn("Something_here");
            totpUtilsMock.when(() -> TotpUtils.qrCode(anyString(), eq(realm), eq(user)))
                         .thenReturn("Something_else_here");

            // Instantiate TotpBean
            TotpBean totpBean = new TotpBean(session, realm, user, uriBuilder);

            // Verify
            assertTrue(totpBean.isEnabled(), "TOTP should be enabled for the user");
            assertEquals(20, totpBean.getTotpSecret().length(),
                    "Expected generated TOTP secret of length 20");

            assertNotNull(totpBean.getTotpSecretEncoded(), "Encoded TOTP secret should not be null");
            assertNotNull(totpBean.getTotpSecretQrCode(), "TOTP secret QR code should not be null");

            assertNotNull(totpBean.getManualUrl(), "Manual URL should not be null or empty");
            assertFalse(totpBean.getManualUrl().isEmpty(), "Manual URL should not be empty");

            assertNotNull(totpBean.getQrUrl(), "QR URL should not be null or empty");
            assertFalse(totpBean.getQrUrl().isEmpty(), "QR URL should not be empty");

            assertNotNull(totpBean.getPolicy(), "OTP Policy should not be null");
            assertFalse(totpBean.getSupportedApplications().isEmpty(),
                    "Supported applications should not be empty");
            assertFalse(totpBean.getOtpCredentials().isEmpty(),
                    "OTP credentials should not be empty");
        }
    }

    @Test
    void testTotpBeanDisabled() throws Exception {
        SubjectCredentialManager credentialManager = user.credentialManager();
        when(credentialManager.isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(false);

        try (var totpUtilsMock = mockStatic(TotpUtils.class)) {
            // Ensure TotpUtils.qrCode returns a dummy value to avoid NPE.
            totpUtilsMock.when(() -> TotpUtils.qrCode(anyString(), eq(realm), eq(user)))
                         .thenReturn("Something_else_here");

            TotpBean totpBean = new TotpBean(session, realm, user, uriBuilder);

            assertTrue(totpBean.getOtpCredentials().isEmpty(),
                    "OTP credentials should be empty when TOTPs are not configured");
        }
    }

    @Test
    void testTotpBeanEnabledEmptyList() throws Exception {
        SubjectCredentialManager credentialManager = user.credentialManager();
        when(credentialManager.isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(true);
        when(credentialManager.getStoredCredentialsByTypeStream(any()))
                .thenReturn(Stream.empty());

        var credentialRepresentation = new org.keycloak.representations.idm.CredentialRepresentation();
        try (var credentialHelperMock = mockStatic(CredentialHelper.class);
             var repToModelMock = mockStatic(RepresentationToModel.class);
             var totpUtilsMock = mockStatic(TotpUtils.class)) {

            credentialHelperMock.when(() ->
                    CredentialHelper.createUserStorageCredentialRepresentation(OTPCredentialModel.TYPE)
            ).thenReturn(credentialRepresentation);

            var credentialModelMock = mock(CredentialModel.class);
            repToModelMock.when(() ->
                    RepresentationToModel.toModel(credentialRepresentation)
            ).thenReturn(credentialModelMock);

            totpUtilsMock.when(() -> TotpUtils.qrCode(anyString(), eq(realm), eq(user)))
                         .thenReturn("Something_else_here");

            TotpBean totpBean = new TotpBean(session, realm, user, uriBuilder);

            assertTrue(totpBean.isEnabled(),
                    "Expected TOTP to be considered enabled when user is configured");
            assertEquals(1, totpBean.getOtpCredentials().size(),
                    "There should be exactly one OTP credential after user-storage fallback");
            assertFalse(totpBean.getOtpCredentials().isEmpty(),
                    "OTP Credentials should not be empty with fallback");
        }
    }
}
