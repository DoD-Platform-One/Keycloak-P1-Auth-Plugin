<div>
  <ul class="step-counter">
    <li class="step step-1 current active">
      <span class="sr-only">Step&nbsp;</span>
      <span>1</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-2">
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
  </ul>
</div>

<!-- Step 2 content - MFA setup -->
<div class="${properties.kcFormClass!}" id="kc-totp-settings-section">
  <div class="mfa-container">
    <h1>Step 2: No CAC? Associate MFA with your account</h1>

    <div class="mfa-qr-container">
      <div class="mfa-instructions">
        <h2>Instructions</h2>
        <ol>
          <li>Install an authenticator app on your mobile device
            <ul>
              <#if totp?? && totp.supportedApplications??>
                <#list totp.supportedApplications as app>
                  <li>${msg(app)}</li>
                </#list>
              <#else>
                <li><a href="https://support.google.com/accounts/answer/1066447" target="_blank">Google Authenticator<span class="icon append ext"></span></a></li>
                <li><a href="https://support.microsoft.com/en-us/account-billing/download-microsoft-authenticator-351498fc-850a-45da-b7b6-27e523b8702a" target="_blank">Microsoft Authenticator<span class="icon append ext"></span></a></li>
                <li><a href="https://bitwarden.com/products/authenticator/" target="_blank">Bitwarden<span class="icon append ext"></span></a></li>
                <li>etc.</li>
              </#if>
            </ul>
          </li>
          <li>Open the application and scan the QR code.<br />
            Note: The barcode changes each time you submit.
          </li>
          <li>Enter the 6-digit code, give your device an optional name and continue.</li>
        </ol>
      </div>

      <div>
        <div class="mfa-qr-code">
          <#if totp?? && totp.totpSecretQrCode??>
            <img id="kc-totp-secret-qr-code" src="data:image/png;base64, ${totp.totpSecretQrCode}" alt="QR Code">
          <#else>
            <!-- QR code placeholder when not available -->
            <img src="${url.resourcesPath}/img/qr-placeholder.png" alt="QR Code" />
          </#if>
        </div>

        <div class="scan-button">Scan me with your MFA app</div>
        <#if totp?? && totp.manualUrl??>
          <div style="margin-top: 10px; text-align: center;">
            <a href="${totp.manualUrl}" id="mode-manual" style="color: #4ce0a3; text-decoration: none;">Can't scan? Enter manually</a>
          </div>
        </#if>
      </div>
    </div>

    <div class="flex container--mfa-code text-center">
      <div class="container--mfa-code-input flex-1">
        <h3>6 Digit MFA Code</h3>
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

      <div class="mfa-device-name flex-1">
    <h3>Device Name <#if totp?? && totp.otpCredentials?? && totp.otpCredentials?size gte 1><span style="color: #ff5555;">*</span><#else>(optional)</#if></h3>
      <input type="text" id="userLabel" name="userLabel" placeholder="Personal cell phone" aria-invalid="<#if messagesPerField.existsError('userLabel')>true</#if>" />
        <#if messagesPerField.existsError('userLabel')>
          <span id="input-error-otp-label" class="${properties.kcInputErrorMessageClass!}" aria-live="polite" style="color: #ff5555; display: block; margin-top: 5px;">
            ${kcSanitize(messagesPerField.get('userLabel'))?no_esc}
          </span>
        </#if>
      </div>
    </div>

    <!-- Hidden fields -->
    <#if totp?? && totp.totpSecret??>
      <input type="hidden" id="totpSecret" name="totpSecret" value="${totp.totpSecret}" />
    </#if>
    <#if mode??>
      <input type="hidden" id="mode" name="mode" value="${mode}"/>
    </#if>

    <!-- Submit button -->
    <div style="margin-top: 30px;">
      <span class="icon prepend lock"></span><input type="submit" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" id="saveTOTPBtn" value="Submit & Continue" ><span class="icon append arrow-right"></span></input>
    </div>
  </div>
</div>

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
      document.getElementById('multi-step-form').submit();
    });
  });
</script>
