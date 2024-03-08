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

package org.keycloak.forms.account.freemarker.model;

import static org.keycloak.utils.CredentialHelper.createUserStorageCredentialRepresentation;

import jakarta.ws.rs.core.UriBuilder;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.authentication.otp.OTPApplicationProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.utils.TotpUtils;

/**
 * This class represents Time-based One-Time Password (TOTP) configuration and information for a
 * user in a realm.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class TotpBean {

  /** The realm associated with the user. */
  private final RealmModel realm;

  /** The TOTP secret. */
  private final String totpSecret;

  /** The encoded TOTP secret. */
  private final String totpSecretEncoded;

  /** The TOTP secret QR code. */
  private final String totpSecretQrCode;

  /** Indicates whether TOTP is enabled for the user. */
  private final boolean enabled;

  /** The URI builder for generating URLs. */
  private UriBuilder uriBuilder;

  /** The list of OTP credentials associated with the user. */
  private final List<CredentialModel> otpCredentials;

  /** The list of supported TOTP applications. */
  private final List<String> supportedApplications;

  /** The length of the TOTP secret. */
  private static final int TOTP_SECRET_LENGTH = 20;

  /**
   * Constructs a {@code TotpBean} object with the specified realm, user, and URI builder.
   *
   * @param kcSession    The Keycloak session.
   * @param realmModel   The realm associated with the user.
   * @param user         The user for whom TOTP is configured.
   * @param uriBldr      The URI builder for generating URLs.
   */
  public TotpBean(
      final KeycloakSession kcSession,
      final RealmModel realmModel,
      final UserModel user,
      final UriBuilder uriBldr) {
    this.uriBuilder = uriBldr;
    this.enabled = user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE);
    if (enabled) {
      List<CredentialModel> otpCredentialList =
          user.credentialManager()
              .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
              .collect(Collectors.toList());

      if (otpCredentialList.isEmpty()) {
        // Credential is configured on userStorage side. Create the "fake" credential similar like
        // we do for the new account console
        CredentialRepresentation credential =
            createUserStorageCredentialRepresentation(OTPCredentialModel.TYPE);
        this.otpCredentials = Collections.singletonList(RepresentationToModel.toModel(credential));
      } else {
        this.otpCredentials = otpCredentialList;
      }
    } else {
      this.otpCredentials = Collections.emptyList();
    }

    this.realm = realmModel;
    this.totpSecret = HmacOTP.generateSecret(TOTP_SECRET_LENGTH);
    this.totpSecretEncoded = TotpUtils.encode(totpSecret);
    this.totpSecretQrCode = TotpUtils.qrCode(totpSecret, realmModel, user);

    OTPPolicy otpPolicy = realmModel.getOTPPolicy();
    this.supportedApplications =
        kcSession.getAllProviders(OTPApplicationProvider.class).stream()
            .filter(p -> p.supports(otpPolicy))
            .map(OTPApplicationProvider::getName)
            .collect(Collectors.toList());
  }

  /**
   * Checks whether TOTP is enabled for the user.
   *
   * @return {@code true} if TOTP is enabled, {@code false} otherwise.
   */
  public boolean isEnabled() {
    return enabled;
  }

  /**
   * Gets the TOTP secret.
   *
   * @return The TOTP secret.
   */
  public String getTotpSecret() {
    return totpSecret;
  }

  /**
   * Gets the encoded TOTP secret.
   *
   * @return The encoded TOTP secret.
   */
  public String getTotpSecretEncoded() {
    return totpSecretEncoded;
  }

  /**
   * Gets the TOTP secret QR code.
   *
   * @return The TOTP secret QR code.
   */
  public String getTotpSecretQrCode() {
    return totpSecretQrCode;
  }

  /**
   * Gets the manual URL for TOTP configuration.
   *
   * @return The manual URL for TOTP configuration.
   */
  public String getManualUrl() {
    return uriBuilder.replaceQueryParam("mode", "manual").build().toString();
  }

  /**
   * Gets the QR URL for TOTP configuration.
   *
   * @return The QR URL for TOTP configuration.
   */
  public String getQrUrl() {
    return uriBuilder.replaceQueryParam("mode", "qr").build().toString();
  }

  /**
   * Gets the TOTP policy for the realm.
   *
   * @return The TOTP policy for the realm.
   */
  public OTPPolicy getPolicy() {
    return realm.getOTPPolicy();
  }

  /**
   * Gets the list of supported TOTP applications.
   *
   * @return The list of supported TOTP applications.
   */
  public List<String> getSupportedApplications() {
    return supportedApplications;
  }

  /**
   * Gets the list of OTP credentials associated with the user.
   *
   * @return The list of OTP credentials associated with the user.
   */
  public List<CredentialModel> getOtpCredentials() {
    return otpCredentials;
  }
}
