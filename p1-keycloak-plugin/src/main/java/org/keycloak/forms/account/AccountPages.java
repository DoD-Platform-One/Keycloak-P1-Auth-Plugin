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

/**
 * Enumeration representing different pages related to user accounts.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public enum AccountPages {
    /** The main account page. */
    ACCOUNT,

    /** The page for managing passwords. */
    PASSWORD,

    /** The page for Two-Factor Authentication (TOTP). */
    TOTP,

    /** The page for managing federated identities. */
    FEDERATED_IDENTITY,

    /** The log page for account activities. */
    LOG,

    /** The sessions page for managing active sessions. */
    SESSIONS,

    /** The applications page for managing connected applications. */
    APPLICATIONS,

    /** The resources page for managing account resources. */
    RESOURCES,

    /** The detailed view of a specific resource. */
    RESOURCE_DETAIL;
}
