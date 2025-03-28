package org.keycloak.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class AccountUrlsTest {

    @Test
    public void testAccountUrlsDefault() {

        String redirectUrl = "http://redirect.com";
        String baseUrl = "http://example.com";
        String realmUrl = baseUrl + "/realms";
        String testRealmUrl = realmUrl + "/testRealm";
        String accountUrl = testRealmUrl + "/account";

        String passwordUrl = accountUrl + "/password";
        String applicationsUrl = accountUrl + "/applications";
        String identityUrl = accountUrl + "/identity";
        String totpUrl = accountUrl + "/totp";
        String logUrl = accountUrl + "/log";
        String sessionsUrl = accountUrl + "/sessions";
        String resourceUrl = accountUrl + "/resource";

        String testTokenUrl = testRealmUrl + "/protocol/openid-connect/logout?post_logout_redirect_uri=http%3A%2F%2Fredirect.com&id_token_hint=testToken";

        String testResourceUrl = resourceUrl + "/testResource";
        String grantUrl = testResourceUrl + "/grant";
        String shareUrl = testResourceUrl + "/share";

        URI baseUri = URI.create(baseUrl);
        URI redirectUri = URI.create(redirectUrl);
        String realmName = "testRealm";
        String idToken = "testToken";
        String resourceId = "testResource";

        // Since AccountUrls methods are static, no need to instantiate AccountUrls
        // AccountUrls accountUrls = new AccountUrls();

        // accountApplicationsPage test
        assertEquals(applicationsUrl, AccountUrls.accountApplicationsPage(baseUri, realmName).toString(),
                "accountApplicationsPage should return the correct URL");

        // accountPage test
        assertEquals(accountUrl + "/", AccountUrls.accountPage(baseUri, realmName).toString(),
                "accountPage should return the correct URL");

        // accountPasswordPage test
        assertEquals(passwordUrl, AccountUrls.accountPasswordPage(baseUri, realmName).toString(),
                "accountPasswordPage should return the correct URL");

        // localeCookiePath test
        assertEquals("/realms/testRealm", AccountUrls.localeCookiePath(baseUri, realmName),
                "localeCookiePath should return the correct path");

        // accountFederatedIdentityPage test
        assertEquals(identityUrl, AccountUrls.accountFederatedIdentityPage(baseUri, realmName).toString(),
                "accountFederatedIdentityPage should return the correct URL");

        // accountFederatedIdentityUpdate test
        assertEquals(identityUrl, AccountUrls.accountFederatedIdentityUpdate(baseUri, realmName).toString(),
                "accountFederatedIdentityUpdate should return the correct URL");

        // accountTotpPage test
        assertEquals(totpUrl, AccountUrls.accountTotpPage(baseUri, realmName).toString(),
                "accountTotpPage should return the correct URL");

        // accountLogPage test
        assertEquals(logUrl, AccountUrls.accountLogPage(baseUri, realmName).toString(),
                "accountLogPage should return the correct URL");

        // accountSessionsPage test
        assertEquals(sessionsUrl, AccountUrls.accountSessionsPage(baseUri, realmName).toString(),
                "accountSessionsPage should return the correct URL");

        // accountLogout test
        assertEquals(testTokenUrl, AccountUrls.accountLogout(baseUri, redirectUri, realmName, idToken).toString(),
                "accountLogout should return the correct URL");

        // accountResourcesPage test
        assertEquals(resourceUrl, AccountUrls.accountResourcesPage(baseUri, realmName).toString(),
                "accountResourcesPage should return the correct URL");

        // accountResourceDetailPage test
        assertEquals(testResourceUrl, AccountUrls.accountResourceDetailPage(resourceId, baseUri, realmName).toString(),
                "accountResourceDetailPage should return the correct URL");

        // accountResourceGrant test
        assertEquals(grantUrl, AccountUrls.accountResourceGrant(resourceId, baseUri, realmName).toString(),
                "accountResourceGrant should return the correct URL");

        // accountResourceShare test
        assertEquals(shareUrl, AccountUrls.accountResourceShare(resourceId, baseUri, realmName).toString(),
                "accountResourceShare should return the correct URL");

        // loginActionUpdatePassword test
        // assertEquals(resourceUrl, AccountUrls.loginActionUpdatePassword(baseUri, realmName).toString());

        // loginActionUpdateTotp test
        // assertEquals(resourceUrl, AccountUrls.loginActionUpdateTotp(baseUri, realmName).toString());

        // loginActionEmailVerification test
        // assertEquals(resourceUrl, AccountUrls.loginActionEmailVerification(baseUri, realmName).toString());
    }
}
