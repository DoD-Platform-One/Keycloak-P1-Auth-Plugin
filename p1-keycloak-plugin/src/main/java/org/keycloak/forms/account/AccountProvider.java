/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.forms.account;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.List;
import org.keycloak.events.Event;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.Provider;

/**
 * Interface representing an account provider, extending the general Provider interface.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public interface AccountProvider extends Provider {

    /**
     * Sets the UriInfo for the account provider.
     *
     * @param uriInfo The UriInfo to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setUriInfo(UriInfo uriInfo);

    /**
     * Sets the HttpHeaders for the account provider.
     *
     * @param httpHeaders The HttpHeaders to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setHttpHeaders(HttpHeaders httpHeaders);

    /**
     * Creates a response based on the specified account page.
     *
     * @param page The account page.
     * @return The response generated for the specified page.
     */
    Response createResponse(AccountPages page);

    /**
     * Sets an error response with the given status, message, and parameters.
     *
     * @param status    The HTTP status for the error.
     * @param message   The error message.
     * @param parameters Additional parameters for formatting the message.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setError(Response.Status status, String message, Object... parameters);

    /**
     * Sets multiple errors with the given status and a list of form messages.
     *
     * @param status   The HTTP status for the errors.
     * @param messages The list of form messages representing errors.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setErrors(Response.Status status, List<FormMessage> messages);

    /**
     * Sets a success message with the given message and parameters.
     *
     * @param message    The success message.
     * @param parameters Additional parameters for formatting the message.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setSuccess(String message, Object... parameters);

    /**
     * Sets a warning message with the given message and parameters.
     *
     * @param message    The warning message.
     * @param parameters Additional parameters for formatting the message.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setWarning(String message, Object... parameters);

    /**
     * Sets the user model for the account provider.
     *
     * @param user The user model to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setUser(UserModel user);

    /**
     * Sets the profile form data using the provided MultivaluedMap.
     *
     * @param formData The form data to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setProfileFormData(MultivaluedMap<String, String> formData);

    /**
     * Sets the realm model for the account provider.
     *
     * @param realm The realm model to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setRealm(RealmModel realm);

    /**
     * Sets the referrer information for the account provider.
     *
     * @param referrer An array of referrer strings.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setReferrer(String[] referrer);

    /**
     * Sets the events for the account provider.
     *
     * @param events The list of events to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setEvents(List<Event> events);

    /**
     * Sets the user sessions for the account provider.
     *
     * @param sessions The list of user sessions to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setSessions(List<UserSessionModel> sessions);

    /**
     * Sets whether the password is set for the account provider.
     *
     * @param passwordSet A boolean indicating whether the password is set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setPasswordSet(boolean passwordSet);

    /**
     * Sets the state checker for the account provider.
     *
     * @param stateChecker The state checker to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setStateChecker(String stateChecker);

    /**
     * Sets the ID token hint for the account provider.
     *
     * @param idTokenHint The ID token hint to set.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setIdTokenHint(String idTokenHint);

    /**
     * Sets various features for the account provider.
     *
     * @param social                      Whether social features are supported.
     * @param events                      Whether events are supported.
     * @param passwordUpdateSupported    Whether password update is supported.
     * @param authorizationSupported     Whether authorization is supported.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setFeatures(
            boolean social,
            boolean events,
            boolean passwordUpdateSupported,
            boolean authorizationSupported);

    /**
     * Sets an attribute with the given key and value for the account provider.
     *
     * @param key   The key of the attribute.
     * @param value The value of the attribute.
     * @return The updated AccountProvider instance.
     */
    AccountProvider setAttribute(String key, String value);
}
