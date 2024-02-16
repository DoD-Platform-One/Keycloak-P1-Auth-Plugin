package org.keycloak.forms.account.freemarker.model;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authentication.otp.OTPApplicationProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.keycloak.forms.account.freemarker.model.TotpBean;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.utils.TotpUtils;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.models.utils.RepresentationToModel;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import org.keycloak.utils.CredentialHelper;

@RunWith(PowerMockRunner.class)
@PrepareForTest({HmacOTP.class, TotpUtils.class, CredentialModel.class, CredentialHelper.class, RepresentationToModel.class})
public class TotpBeanTest {

    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private UriBuilder uriBuilder;
    private OTPPolicy otpPolicy;

    @Before
    public void setUp() {
        PowerMockito.mockStatic(HmacOTP.class);
        PowerMockito.mockStatic(TotpUtils.class);

        session = PowerMockito.mock(KeycloakSession.class);
        realm = PowerMockito.mock(RealmModel.class);
        user = PowerMockito.mock(UserModel.class);
        uriBuilder = PowerMockito.mock(UriBuilder.class);
        otpPolicy = PowerMockito.mock(OTPPolicy.class);

        // Mock the credentialManager() method to return a non-null value
        SubjectCredentialManager credentialManager = PowerMockito.mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credentialManager);
    }

    @Test
    public void testTotpBeanEnabled() throws Exception {
        when(user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(true);

        CredentialModel credentialModelMock = PowerMockito.mock(CredentialModel.class);
        when(credentialModelMock.getType()).thenReturn(CredentialModel.TOTP);
        when(credentialModelMock.getSecretData()).thenReturn("totpSecret");
        Collections.singletonList(credentialModelMock);

        when(user.credentialManager().getStoredCredentialsByTypeStream(any())).thenReturn(
                Stream.of(credentialModelMock));

        when(realm.getOTPPolicy()).thenReturn(otpPolicy);

        List<OTPApplicationProvider> applicationProviders = Collections.singletonList(
                PowerMockito.mock(OTPApplicationProvider.class));
        when(session.getAllProviders(OTPApplicationProvider.class)).thenReturn(new java.util.HashSet<>(applicationProviders));
        when(applicationProviders.get(0).supports(otpPolicy)).thenReturn(true);
        when(applicationProviders.get(0).getName()).thenReturn("testApplication");

        when(uriBuilder.replaceQueryParam(eq("mode"), any(String.class))).thenReturn(uriBuilder);
        when(uriBuilder.build()).thenReturn(new URI("http://example.com"));
        when(HmacOTP.generateSecret(20)).thenReturn("20_Characters_needed");

        when(TotpUtils.encode(any(String.class))).thenReturn("Something_here");
        when(TotpUtils.qrCode(any(String.class), eq(realm), eq(user))).thenReturn("Something_else_here");

        TotpBean totpBean = new TotpBean(session, realm, user, uriBuilder);

        assertEquals(true, totpBean.isEnabled());
        assertEquals("Expected TOTP secret length", 20, totpBean.getTotpSecret().length());

        assertNotNull("Encoded TOTP secret should not be null", totpBean.getTotpSecretEncoded());
        assertNotNull("Totp secret QR code should not be null", totpBean.getTotpSecretQrCode());

        // Assuming there's a specific format for manual and QR URLs
        assertNotNull(totpBean.getManualUrl());
        assertFalse(totpBean.getManualUrl().isEmpty());

        assertNotNull(totpBean.getQrUrl());
        assertFalse(totpBean.getQrUrl().isEmpty());

        assertNotNull("OTP policy should not be null", totpBean.getPolicy());

        assertFalse("Supported applications should not be empty", totpBean.getSupportedApplications().isEmpty());

        assertFalse("OTP credentials should not be empty", totpBean.getOtpCredentials().isEmpty());
    }

    @Test
    public void testTotpBeanDisabled() throws Exception {
        when(user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(false);

        TotpBean totpBean = new TotpBean(session, realm, user, uriBuilder);

        assertTrue("OTP Credentials is empty.", totpBean.getOtpCredentials().isEmpty());
    }

    @Test
    public void testTotpBeanEnabledEmptyList() throws Exception {
        // Mock the necessary dependencies
        when(user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(true);
    
        // Mock an empty list of CredentialModel
        List<CredentialModel> emptyCredentialList = Collections.emptyList();
        when(user.credentialManager().getStoredCredentialsByTypeStream(any())).thenReturn(emptyCredentialList.stream());
    
        // Simulate the scenario where the credential is configured on the user storage side
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        PowerMockito.mockStatic(CredentialHelper.class);
        when(CredentialHelper.createUserStorageCredentialRepresentation(OTPCredentialModel.TYPE)).thenReturn(credentialRepresentation);
    
        // Mock the behavior of RepresentationToModel.toModel(credentialRepresentation)
        CredentialModel credentialModelMock = PowerMockito.mock(CredentialModel.class);
        PowerMockito.mockStatic(RepresentationToModel.class);
        when(RepresentationToModel.toModel(credentialRepresentation)).thenReturn(credentialModelMock);
    
        TotpBean totpBean = new TotpBean(session, realm, user, uriBuilder);
    
        // Assertions
        assertTrue(totpBean.isEnabled());
        assertEquals(1, totpBean.getOtpCredentials().size());
        assertFalse("OTP Credentials is empty.", totpBean.getOtpCredentials().isEmpty());
    }
}