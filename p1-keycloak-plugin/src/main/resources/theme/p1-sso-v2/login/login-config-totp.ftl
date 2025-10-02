<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayRequiredFields=false displayMessage=!messagesPerField.existsError('totp','userLabel'); section>

<div class="step-counter-wrapper">
  <ul class="step-counter">
    <li class="step step-0 active">
      <span class="sr-only">Step&nbsp;</span>
      <span>1</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-3 current active">
      <span class="sr-only">Step&nbsp;</span>
      <span>2</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-3">
      <span class="sr-only">Step&nbsp;</span>
      <span>3</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-4">
      <span class="sr-only">Step&nbsp;</span>
      <span>4</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-5">
      <span class="sr-only">Step&nbsp;</span>
      <span>5</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
  </ul>
</div>

<#if section = "header">
  ${msg("loginTotpTitle")}
<#elseif section = "form">
  <h1>Step 2b: Associate MFA with your account</h1>

  <div class="mfa-qr-container">
    <div class="mfa-instructions">
      <h2>Instructions</h2>
      <ol>
        <li>${msg("loginTotpStep1")}
          <ul id="kc-totp-supported-apps">
            <li><a href="https://support.google.com/accounts/answer/1066447" target="_blank">Google Authenticator<span class="icon append ext subtext-2"></span></a></li>
            <li><a href="https://support.microsoft.com/en-us/account-billing/download-microsoft-authenticator-351498fc-850a-45da-b7b6-27e523b8702a" target="_blank">Microsoft Authenticator<span class="icon append ext subtext-2"></span></a></li>
            <li><a href="https://bitwarden.com/products/authenticator/" target="_blank">Bitwarden<span class="icon append ext subtext-2"></span></a></li>
            <li>etc.</li>
          </ul>
        </li>

        <#if mode?? && mode = "manual">
          <li>
            <p>${msg("loginTotpManualStep2")}</p>
            <code id="kc-totp-secret-key" class="code text-lg">${totp.totpSecretEncoded}</code>
            <p><a href="${totp.qrUrl}" class="btn btn-primary outline btn-sm" id="mode-barcode">${msg("loginTotpScanBarcode")}</a></p>
          </li>
          <li>
            <p>${msg("loginTotpManualStep3")}</p>
            <p>
            <ul>
              <li id="kc-totp-type">${msg("loginTotpType")}: ${msg("loginTotp." + totp.policy.type)}</li>
              <li id="kc-totp-algorithm">${msg("loginTotpAlgorithm")}: ${totp.policy.getAlgorithmKey()}</li>
              <li id="kc-totp-digits">${msg("loginTotpDigits")}: ${totp.policy.digits}</li>
              <#if totp.policy.type = "totp">
                <li id="kc-totp-period">${msg("loginTotpInterval")}: ${totp.policy.period}</li>
              <#elseif totp.policy.type = "hotp">
                <li id="kc-totp-counter">${msg("loginTotpCounter")}: ${totp.policy.initialCounter}</li>
              </#if>
            </ul>
            </p>
          </li>
          <!-- TODO: add message about how if you scan the QR code but take too long to verify and registration times out you'll need to get a new code in your authenticator by re-scanning the code as the old one won't work anymore -->
        <#else>
          <li>Open the application and scan the QR code.<br />
            Note: The barcode changes each time you submit.
          </li>
        </#if>
        <li>
          <p>${msg("loginTotpStep3")}</p>
        </li>
      </ol>
    </div>


    <#if mode?? && mode = "manual">
      <div class="hidden">
    </#if>

    <div class="mfa-qr-code">
      <img id="kc-totp-secret-qr-code" src="data:image/png;base64, ${totp.totpSecretQrCode}" alt="Figure: Barcode">
      <div class="scan-button">Scan me with your MFA app</div>
      <p><a href="${totp.manualUrl}" id="mode-manual">${msg("loginTotpUnableToScan")}</a></p>
    </div>

    <#if mode?? && mode = "manual">
      </div>
    </#if>
  </div>















  <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-totp-settings-form" method="post">
    <div class="flex container--mfa-code">

      <div class="${properties.kcFormGroupClass!} flex-1">
        <div class="${properties.kcInputWrapperClass!}">
          <label for="totp" class="control-label fs-3 text-center">${msg("authenticatorCode")}<span class="required">*</span></label> 
        </div>

        <div class="${properties.kcInputWrapperClass!}">
          <!-- Hidden actual input field for form submission -->
          <input type="hidden" id="totp" name="totp" value="" />
          <div class="mfa-code-input">
            <input type="text" class="digit" maxlength="1" data-index="0" placeholder="0"/>
            <input type="text" class="digit" maxlength="1" data-index="1" placeholder="0"/>
            <input type="text" class="digit" maxlength="1" data-index="2" placeholder="0"/>
            <div class="separator">-</div>
            <input type="text" class="digit" maxlength="1" data-index="3" placeholder="0"/>
            <input type="text" class="digit" maxlength="1" data-index="4" placeholder="0"/>
            <input type="text" class="digit" maxlength="1" data-index="5" placeholder="0"/>
          </div>

          <#if messagesPerField.existsError('totp')>
            <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite" style="color: #ff5555; display: block; text-align: center; margin-top: 10px;">
              ${kcSanitize(messagesPerField.get('totp'))?no_esc}
            </span>
          </#if>
        </div>

        <input type="hidden" id="totpSecret" name="totpSecret" value="${totp.totpSecret}" />
      <#if mode??><input type="hidden" id="mode" name="mode" value="${mode}"/></#if>
        </div>

        <div class="${properties.kcFormGroupClass!} flex-1">
          <div class="${properties.kcInputWrapperClass!}">
            <label for="userLabel" class="control-label fs-3">${msg("loginTotpDeviceName")}<#if totp.otpCredentials?size gte 1><span class="required">*</span></#if></label>
          </div>

          <div class="${properties.kcInputWrapperClass!}">
            <input type="text" class="${properties.kcInputClass!}" id="userLabel" name="userLabel" autocomplete="off"
          aria-invalid="<#if messagesPerField.existsError('userLabel')>true</#if>"
            />

            <#if messagesPerField.existsError('userLabel')>
              <span id="input-error-otp-label" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                ${kcSanitize(messagesPerField.get('userLabel'))?no_esc}
              </span>
            </#if>
          </div>
        </div>

    </div>

    <#if isAppInitiatedAction??>
      <button type="submit"
        class="btn ${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!} fl-r"
        id="saveTOTPBtn" value="${msg("doSubmit")} and continue">Submit and continue <span class="icon append arrow-right"></span></button>
      <button type="submit"
        class="btn btn-accent ${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} mx-3 fl-r"
        id="cancelTOTPBtn" name="cancel-aia" value="true" />${msg("doCancel")}
      </button>
    <#else>
      <button type="submit"
        class="${properties.kcButtonClass!} btn ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!} fl-r"
        id="saveTOTPBtn" value="${msg("doSubmit")} and continue">Submit and continue <span class="icon append arrow-right"></span></button>
      </#if>
  </form>
</#if>


<script>
  // Script to handle the digit inputs and combine them into the hidden totp field
  document.addEventListener('DOMContentLoaded', function() {
    const digitInputs = document.querySelectorAll('.digit');
    const totpInput = document.getElementById('totp');

    // Function to update the hidden totp input with all digits
    function updateTotpValue() {
      let code = '';
      digitInputs.forEach(input => {
        code += input.value || '';
      });
      totpInput.value = code;
    }

    // Add event listeners to each digit input
    digitInputs.forEach((input, index) => {
      // Focus next input after entering a digit
      input.addEventListener('input', function() {
        updateTotpValue();
        if (this.value && index < digitInputs.length - 1) {
          digitInputs[index + 1].focus();
        }
      });

      // Handle backspace to go to previous input
      input.addEventListener('keydown', function(e) {
        if (e.key === 'Backspace' && !this.value && index > 0) {
          digitInputs[index - 1].focus();
        }
      });

      // Handle paste event to distribute digits across inputs
      input.addEventListener('paste', function(e) {
        e.preventDefault();
        const pastedData = (e.clipboardData || window.clipboardData).getData('text');
        const digits = pastedData.replace(/\D/g, '').split('');

        digits.forEach((digit, i) => {
          if (index + i < digitInputs.length) {
            digitInputs[index + i].value = digit;
          }
        });

        updateTotpValue();

        // Focus the next empty input or the last input
        let nextEmptyIndex = Array.from(digitInputs).findIndex(input => !input.value);
        if (nextEmptyIndex === -1) nextEmptyIndex = digitInputs.length - 1;
        digitInputs[nextEmptyIndex].focus();
      });
    });

    // Form validation for TOTP code
    document.getElementById('saveTOTPBtn').addEventListener('click', function(e) {
      updateTotpValue();
      const code = totpInput.value;

      if (code.length !== 6 || !/^\d+$/.test(code)) {
        e.preventDefault();
        alert('Please enter a valid 6-digit code');
        return false;
      }

      // If valid, let the parent form handle the submission
      // Submit the correct form that contains these inputs
      document.getElementById('kc-totp-settings-form').submit();
    });
  });
</script>
</@layout.registrationLayout>

