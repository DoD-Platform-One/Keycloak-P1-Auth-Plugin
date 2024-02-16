 package org.keycloak.services;

 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.powermock.core.classloader.annotations.PrepareForTest;
 import org.powermock.modules.junit4.PowerMockRunner;

 import java.net.URI;

 import static org.junit.Assert.assertEquals;

 @RunWith(PowerMockRunner.class)
 @PrepareForTest({URI.class})
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

         // accountApplicationsPage test
         assertEquals(applicationsUrl, AccountUrls.accountApplicationsPage(baseUri, realmName).toString());

         // accountPage test
         assertEquals(accountUrl + "/", AccountUrls.accountPage(baseUri, realmName).toString());

         // accountPasswordPage test
         assertEquals(passwordUrl, AccountUrls.accountPasswordPage(baseUri, realmName).toString());

         // localeCookiePath test
         assertEquals("/realms/testRealm", AccountUrls.localeCookiePath(baseUri, realmName));

         // accountFederatedIdentityPage test
         assertEquals(identityUrl, AccountUrls.accountFederatedIdentityPage(baseUri, realmName).toString());

         // accountFederatedIdentityUpdate test
         assertEquals(identityUrl, AccountUrls.accountFederatedIdentityUpdate(baseUri, realmName).toString());

         // accountTotpPage test
         assertEquals(totpUrl, AccountUrls.accountTotpPage(baseUri, realmName).toString());

         // accountLogPage test
         assertEquals(logUrl, AccountUrls.accountLogPage(baseUri, realmName).toString());

         // accountSessionsPage test
         assertEquals(sessionsUrl, AccountUrls.accountSessionsPage(baseUri, realmName).toString());

         // accountLogout test
         assertEquals(testTokenUrl, AccountUrls.accountLogout(baseUri, redirectUri, realmName, idToken).toString());

         // accountResourcesPage test
         assertEquals(resourceUrl, AccountUrls.accountResourcesPage(baseUri, realmName).toString());

         // accountResourceDetailPage test
         assertEquals(testResourceUrl, AccountUrls.accountResourceDetailPage(resourceId, baseUri, realmName).toString());

         // accountResourceGrant test
         assertEquals(grantUrl, AccountUrls.accountResourceGrant(resourceId, baseUri, realmName).toString());

         // accountResourceShare test
         assertEquals(shareUrl, AccountUrls.accountResourceShare(resourceId, baseUri, realmName).toString());

         // loginActionUpdatePassword test
//         assertEquals(resourceUrl, AccountUrls.loginActionUpdatePassword(baseUri, realmName).toString());

         // loginActionUpdateTotp test
//         assertEquals(resourceUrl, AccountUrls.loginActionUpdateTotp(baseUri, realmName).toString());

         // loginActionEmailVerification test
//         assertEquals(resourceUrl, AccountUrls.loginActionEmailVerification(baseUri, realmName).toString());
     }
 }