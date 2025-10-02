<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('otp') displayRequiredFields=true; section>

<#if section = "header">
  ${msg("doLogIn")}<!-- Use a standard message key -->
<#elseif section = "form">
  <div id="kc-form-login-otp" class="login-otp">
    <h1 id="kc-page-title" class="text-center w-100">MFA Sign in</h1>
    <p class="subtitle">6 Digit MFA Code</p>

    <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
      <div class="${properties.kcFormGroupClass!}">
        <!-- Hidden actual input field for form submission -->
        <input type="hidden" id="otp" name="otp" value="" /> <!-- Keycloak usually expects 'otp' here -->

        <div class="mfa-code-input">
          <input type="text" class="digit" maxlength="1" data-index="0" pattern="[0-9]" inputmode="numeric" autocomplete="off" autofocus/>
          <input type="text" class="digit" maxlength="1" data-index="1" pattern="[0-9]" inputmode="numeric" autocomplete="off"/>
          <input type="text" class="digit" maxlength="1" data-index="2" pattern="[0-9]" inputmode="numeric" autocomplete="off"/>
          <div class="separator">-</div>
          <input type="text" class="digit" maxlength="1" data-index="3" pattern="[0-9]" inputmode="numeric" autocomplete="off"/>
          <input type="text" class="digit" maxlength="1" data-index="4" pattern="[0-9]" inputmode="numeric" autocomplete="off"/>
          <input type="text" class="digit" maxlength="1" data-index="5" pattern="[0-9]" inputmode="numeric" autocomplete="off"/>
        </div>

        <#if messagesPerField.existsError('otp')> <!-- Check for error related to 'otp' -->
          <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
            ${kcSanitize(messagesPerField.get('otp'))?no_esc}
          </span>
        </#if>
      </div>

      <div class="help-text">
        Trouble logging in? Visit the <a href="/auth/realms/${realm.name}/onboarding/faq" target="_blank">FAQ Page</a> or email us at <a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a>
      </div>

      <div class="${properties.kcFormGroupClass!} ${properties.kcFormButtonsClass!} flex justify-center flex-wrap gap-3">
        <input type="hidden" id="id-hidden-input" name="credentialId" /> <!-- Simplified credentialId -->
        <!-- Add a real cancel button if possible, otherwise link -->
        <a class="btn btn-accent outline" href="${url.loginRestartFlowUrl}">Cancel</a> <!-- Or link to base URL -->
        <button type="submit" class="btn btn-primary ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login">
           <span class="icon prepend lock"></span>Confirm & log in<span class="icon append arrow-right"></span>
        </button>
      </div>
    </form>
  </div>

  <#-- Include script for handling digit inputs -->
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const digitInputs = document.querySelectorAll('.digit');
      const otpInput = document.getElementById('otp'); // Target the hidden 'otp' input
      const form = document.getElementById('kc-otp-login-form');

      function updateOtpValue() {
        let code = '';
        digitInputs.forEach(input => {
          code += input.value || ''; // Append digit or empty string if input is empty
        });
        otpInput.value = code;
        console.log("Updated OTP value:", otpInput.value); // Debug log
      }

      digitInputs.forEach((input, index) => {
        input.addEventListener('input', function(e) {
          // Ensure only digits are entered (though pattern helps)
          this.value = this.value.replace(/[^0-9]/g, '');

          updateOtpValue(); // Update hidden input on every input event

          // Auto-focus next input if a digit is entered
          if (this.value && index < digitInputs.length - 1) {
            digitInputs[index + 1].focus();
          }
        });

        input.addEventListener('keydown', function(e) {
          // Handle Backspace: Move to previous input if current is empty
          if (e.key === 'Backspace' && !this.value && index > 0) {
            digitInputs[index - 1].focus();
            // Update value after potential backspace in previous field if needed
            setTimeout(updateOtpValue, 0);
          }
          // Handle ArrowLeft: Move to previous input
          else if (e.key === 'ArrowLeft' && index > 0) {
             e.preventDefault(); // Prevent default cursor movement
             digitInputs[index - 1].focus();
          }
          // Handle ArrowRight: Move to next input
          else if (e.key === 'ArrowRight' && index < digitInputs.length - 1) {
             e.preventDefault(); // Prevent default cursor movement
             digitInputs[index + 1].focus();
          }
        });

        // Handle paste event
        input.addEventListener('paste', function(e) {
          e.preventDefault();
          const pastedData = (e.clipboardData || window.clipboardData).getData('text');
          const digits = pastedData.replace(/\D/g, '').split(''); // Get only digits

          digits.forEach((digit, i) => {
            const targetIndex = index + i;
            if (targetIndex < digitInputs.length) {
              digitInputs[targetIndex].value = digit;
            }
          });

          updateOtpValue(); // Update hidden input after pasting

          // Focus the next empty input or the last input after paste
          let nextFocusIndex = Array.from(digitInputs).findIndex((inp, idx) => idx >= index && !inp.value);
          if (nextFocusIndex === -1 || nextFocusIndex > digitInputs.length - 1) {
              nextFocusIndex = digitInputs.length - 1; // Focus last input if all filled or paste goes beyond
          }
          digitInputs[nextFocusIndex].focus();
        });
      });

      // Optional: Add form submission validation if needed,
      // but Keycloak usually handles the OTP validation server-side.
      // form.addEventListener('submit', function(e) {
      //   updateOtpValue(); // Ensure value is up-to-date before submit
      //   if (otpInput.value.length !== 6) {
      //     e.preventDefault();
      //     // Display an error message locally if desired
      //     console.error("OTP code must be 6 digits.");
      //   }
      // });
    });
  </script>

</#if>

<!-- Removed extra closing #if -->
</@layout.registrationLayout>
