<div>
  <ul class="step-counter">
    <li class="step step-0 current active">
      <span class="sr-only">Step&nbsp;</span>
      <span>1</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-1">
      <span class="sr-only">Step&nbsp;</span>
      <span>2</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-2">
      <span class="sr-only">Step&nbsp;</span>
      <span>3</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-3">
      <span class="sr-only">Step&nbsp;</span>
      <span>4</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
  </ul>
</div>

<#if section = "form">
  <h2>Step 1: Create your account</h2>

  <#-- Display general error messages from the server -->
  <#if message?has_content>
    <div class="alert alert-${message.type} p-4 mb-4 text-sm rounded-lg <#if message.type = 'success'>bg-green-100 text-green-700<#elseif message.type = 'warning'>bg-yellow-100 text-yellow-700<#elseif message.type = 'error'>bg-red-100 text-red-700<#else>bg-blue-100 text-blue-700</#if>" role="alert">
      <#-- Optional: Add icons based on message type if your theme supports them -->
      <span class="font-medium">${kcSanitize(message.summary)?no_esc}</span>
    </div>
  </#if>
  <#if cacIdentity??>
    <div class="alert alert-success cac-info">
      <p class="title">DoD PKI (CAC) User Registration</p>
      <p><b>CAC Identity:</b> ${cacIdentity}</p>
      <p><b>Note:</b> Your CAC will automatically be associated with your account.</p>
    </div>

    <#-- Add hidden fields to pass CAC information to step4 -->
    <input type="hidden" name="user.attributes.cacIdentity" value="${cacIdentity}">
    <#if x509?? && x509.notAfter??>
      <input type="hidden" name="user.attributes.cacExpiration" value="${x509.notAfter}">
    <#elseif x509?? && x509.formData?? && x509.formData.notAfter??>
      <input type="hidden" name="user.attributes.cacExpiration" value="${x509.formData.notAfter}">
    </#if>

  <#else>
    <div class="alert alert-warning cac-info">
      <p class="title">MFA User Registration (no DoD PKI/CAC detected)</p>
      <p>If you do not have a CAC, you will set up Two-Factor Authentication (MFA) in the next step.  If you do have a CAC, make sure your CAC reader is connected properly and reload this window.</p>
      <p>Your company or government email address is preferred for registration. Your access will be based off of your validated email address.</p>
      <p>For assistance contact your onboarding supervisor or email us at <a id="helpdesk" href="mailto:mailto:${msg("helpEmail")}">${msg("helpEmail")}</a>.
      </p>
    </div>
  </#if>

  <div class="row">
      <div class="form-group">
        <label for="firstName" class="form-label">First name</label>
        <input type="text" id="firstName" class="form-control" name="firstName"
        value="${(register.formData.firstName!'')}"/>
      </div>

      <div class="form-group">
        <label for="lastName" class="form-label">Last name</label>
        <input type="text" id="lastName" class="form-control" name="lastName"
        value="${(register.formData.lastName!'')}"/>
      </div>
  </div>

  <div class="row">
    <div class="form-group">
      <label for="user.attributes.affiliation" class="form-label">Affiliation</label>
      <select id="user.attributes.affiliation" name="user.attributes.affiliation" class="form-control">
        <option selected="" disabled="" hidden="">Select your org</option>
        <optgroup label="US Government">
          <option>US Air Force</option>
          <option>US Air Force Reserve</option>
          <option>US Air National Guard</option>
          <option>US Army</option>
          <option>US Army Reserve</option>
          <option>US Army National Guard</option>
          <option>US Coast Guard</option>
          <option>US Coast Guard Reserve</option>
          <option>US Marine Corps</option>
          <option>US Marine Corps Reserve</option>
          <option>US Navy</option>
          <option>US Navy Reserve</option>
          <option>US Space Force</option>
          <option>Dept of Defense</option>
          <option>Federal Government</option>
          <option>Other</option>
        </optgroup>

        <optgroup label="Contractor">
          <option>A&AS</option>
          <option>Contractor</option>
          <option>FFRDC</option>
          <option>Other</option>
        </optgroup>
      </select>
    </div>

      <div class="form-group">
        <label for="user.attributes.rank" class="form-label">Pay Grade</label>
        <select id="user.attributes.rank" name="user.attributes.rank" class="form-control">
          <option selected="" disabled="" hidden="">Select your rank</option>
          <optgroup label="Enlisted">
            <option>E-1</option>
            <option>E-2</option>
            <option>E-3</option>
            <option>E-4</option>
            <option>E-5</option>
            <option>E-6</option>
            <option>E-7</option>
            <option>E-8</option>
            <option>E-9</option>
          </optgroup>

          <optgroup label="Warrant Officer">
            <option>W-1</option>
            <option>W-2</option>
            <option>W-3</option>
            <option>W-4</option>
            <option>W-5</option>
          </optgroup>

          <optgroup label="Officer">
            <option>O-1</option>
            <option>O-2</option>
            <option>O-3</option>
            <option>O-4</option>
            <option>O-5</option>
            <option>O-6</option>
            <option>O-7</option>
            <option>O-8</option>
            <option>O-9</option>
            <option>O-10</option>
          </optgroup>

          <optgroup label="Civil Service">
            <option>GS-1</option>
            <option>GS-2</option>
            <option>GS-3</option>
            <option>GS-4</option>
            <option>GS-5</option>
            <option>GS-6</option>
            <option>GS-7</option>
            <option>GS-8</option>
            <option>GS-9</option>
            <option>GS-10</option>
            <option>GS-11</option>
            <option>GS-12</option>
            <option>GS-13</option>
            <option>GS-14</option>
            <option>GS-15</option>
            <option>SES</option>
          </optgroup>
          <option>N/A</option>
        </select>
      </div>
  </div>

  <div class="form-group">
    <label for="user.attributes.organization" class="form-label">Unit, Organization, or Company Name</label>
    <input id="user.attributes.organization" class="form-control" name="user.attributes.organization" type="text"
    value="${(register.formData['user.attributes.organization']!'')}" autocomplete="company"/>
  </div>
  <div class="form-group">
    <label for="user.attributes.location" class="form-label">Location</label>
    <input id="user.attributes.location" class="form-control" name="user.attributes.location" type="text" />
  </div>

  <#-- Mattermost Persona Field (Optional) -->
  <div class="form-group">
    <label for="user.attributes.persona" class="form-label">
      Mattermost Access Code 
      <span class="text-muted">(Optional)</span>
    </label>
    <input id="user.attributes.persona" 
           class="form-control" 
           name="user.attributes.persona" 
           type="text"
           placeholder="e.g., 123-ORG-role"
           value="${(register.formData['user.attributes.persona']!'')}" />
    <p class="description">If you were provided a Mattermost access code in your onboarding email, enter it here. Format: ###-ORG-role</p>
    <div id="persona-format-warning" style="display:none;" class="text-warning">
      Access code should be in the format: ###-ORG-role (e.g., 123-TEST-developer)
    </div>
  </div>

  <div class="form-group">
    <label for="email" class="form-label">${msg("email")}</label>
    <input id="email" class="form-control" name="email" type="text" placeholder="john.doe.3@us.af.mil"
    value="${(register.formData.email!'')}" autocomplete="email"/>
  </div>

  <div class="form-group">
    <label for="confirmEmail" class="form-label">Confirm Email</label>
    <input id="confirmEmail" class="form-control" name="confirmEmail" type="text" placeholder="john.doe.3@us.af.mil"
    value="${(register.formData.confirmEmail!'')}" autocomplete="email"/>
    <div id="email-mismatch-error" style="display:none;" class="text-error">Email addresses do not match</div>
  </div>

  <#if !realm.registrationEmailAsUsername>
    <div class="form-group">
      <label for="username" class="form-label">${msg("username")}</label>
      <input id="username" class="form-control" name="username" type="text" placeholder="john.doe.3"
      value="${(register.formData.username!'')}" autocomplete="username"/>
      <p class="description">Strongly recommend to use your email prefix, e.g. "john.doe.3"</p>
    </div>
  </#if>

  <#-- <div class="form-group">
    <div class="checkbox">
      <label>
        <input type="checkbox" id="toggle-uid" name="toggle-uid"> I received a Platform One Unit Identifier (UID) via email
      </label>
      <p class="description">Most people will not have this. If you think you should have one, reach out to your Onboarding Supervisor</p>
    </div>
  </div>

   <div id="uid-section" style="display:none;" class="form-group">
    <label for="user.attributes.uid" class="form-label">Your Platform One Unit Identifier (UID)</label>
    <input type="text" id="user.attributes.uid" class="form-control" name="user.attributes.uid"
    placeholder="123-456-789" pattern="\d{3}-\d{3}-\d{3}"
    value="${(register.formData['user.attributes.uid']!'')}" />
    <div id="uid-format-error" class="text-error">UID must be in the format 123-456-789</div>
  </div>

  <div class="form-group">
    <label for="user.attributes.notes" class="form-label ">${msg("accessRequest")}</label>
    <textarea id="user.attributes.notes" class="form-control " name="user.attributes.notes"></textarea>
  </div>  -->
  <#if cacIdentity??>
  <div class="form-group">
    <div class="checkbox">
      <label>
        <input type="checkbox" id="toggle-password" name="toggle-password"> I want to set a password now (optional for CAC users)
      </label>
      <p class="description">If you are registering with a CAC, a password is not required but is recommended as a backup.</p>
    </div>
  </div>
  </#if>

  <div id="password-section" class="form-group" <#if cacIdentity??>style="display:none;"</#if>>
    <#if cacIdentity??>
      <div class="alert alert-info cac-info text-white">
        <p>${msg("passwordCacMessage1")}</p>
        <p class="text-orange">${msg("passwordCacMessage2")}</p>
        <p>${msg("passwordCacMessage3")}</p>
      </div>
      <label for="password" class="form-label ">${msg("passwordOptional")}</label>
    <#else>
      <label for="password" class="form-label ">${msg("password")}</label>
    </#if>

    <div id="top-caps-lock-warning" style="display: none;" class="text-error">CAPS LOCK IS ON</div>

    <input id="password" class="form-control" name="password" type="password" autocomplete="new-password"/>
    <label><input type="checkbox" id="show-password-checkbox"> Show Password</label>


    <div id="password-requirements">
      <p>Password Requirements:</p>
      <ul>
        <li id="password-length" class="text-error">At least 15 characters</li>
        <li id="password-uppercase" class="text-error">At least one uppercase letter</li>
        <li id="password-lowercase" class="text-error">At least one lowercase letter</li>
        <li id="password-numeric" class="text-error">At least one number</li>
        <li id="password-special" class="text-error">At least two special characters <i>(<span class="font-mono"> @, #</span> )</i></li>
      </ul>
    </div>

    <div class="form-group" id="password-confirm-group" style="display: none;">
      <label for="password-confirm" class="form-label" id="password-confirm-label">${msg("passwordConfirm")}</label>
      <input id="password-confirm" class="form-control" name="password-confirm" type="password" autocomplete="new-password"/>
      <!-- Removed redundant show password checkbox -->
      <div id="bottom-caps-lock-warning" style="display: none;" class="text-error">CAPS LOCK IS ON</div>
      <div id="password-mismatch-error" style="display: none;" class="text-error">Passwords do not match</div>
    </div>
  </div>


  <script>
    // Add event listener to skip step 3 if CAC is detected
    document.addEventListener('DOMContentLoaded', () => {
      const nextBtn = document.getElementById('next-step');
    const hasCac = <#if cacIdentity??>true<#else>false</#if>;

    if (hasCac) {
      const togglePasswordCheckbox = document.getElementById('toggle-password');
      const passwordSection = document.getElementById('password-section');

      if (togglePasswordCheckbox && passwordSection) {
          togglePasswordCheckbox.addEventListener('change', function () {
              if (this.checked) {
                  passwordSection.style.display = 'block';
              } else {
                  passwordSection.style.display = 'none';
              }
          });
      }
    }

      if (hasCac && nextBtn) {
        // Override the default next button click handler for step 2
        nextBtn.addEventListener('click', function(e) {
          const currentStepValue = document.getElementById('step').value;

          // If we're on step 2 and have CAC, skip to step 3 (review page)
          if (currentStepValue === '2') {
            // --- Add Validation Call ---
            // validateStep2 is defined in the parent register.ftl scope
            if (typeof validateStep2 === 'function' && !validateStep2()) {
              console.log("Step 2 validation failed (CAC path).");
              return; // Stop if validation fails
            }
            console.log("Step 2 validation passed (CAC path).");
            // --- End Validation Call ---
            e.stopPropagation(); // Stop the default handler

            // Get all step content elements
            const steps = document.querySelectorAll('.step-content');
            const stepInput = document.getElementById('step');
            const prevBtn = document.getElementById('prev-step');
            const nextBtn = document.getElementById('next-step');
            const submitBtn = document.getElementById('submit-form');

            // Skip to step 3 (review page)
            const newStep = 2;

            // Hide all steps and show step 4
            steps.forEach(s => {
              s.classList.toggle('hidden', parseInt(s.dataset.step) !== newStep);
            });

            // Update step input value
            stepInput.value = newStep;

            // Update button visibility
            prevBtn.classList.remove('hidden');
            nextBtn.classList.add('hidden');
            submitBtn.classList.remove('hidden');

            // Manually populate the review data in step 4
            setTimeout(() => {
              // Call the populateReviewData function from step4.ftl
              const populateReviewData = function() {
                // Get form elements
                const firstName = document.getElementById('firstName');
                const lastName = document.getElementById('lastName');
                const email = document.getElementById('email');
                const confirmEmail = document.getElementById('confirmEmail');
                const username = document.getElementById('username');
                const affiliation = document.getElementById('user.attributes.affiliation');
                const rank = document.getElementById('user.attributes.rank');
                const organization = document.getElementById('user.attributes.organization');
                const notes = document.getElementById('user.attributes.notes');

                // Populate review fields
                if (firstName && lastName) {
                  const reviewName = document.getElementById('review-name');
                  if (reviewName) {
                    reviewName.textContent = firstName.value + ' ' + lastName.value;
                  }
                }

                if (email) {
                  const reviewEmail = document.getElementById('review-email');
                  if (reviewEmail) {
                    reviewEmail.textContent = email.value;
                  }
                }

                if (affiliation) {
                  const reviewAffiliation = document.getElementById('review-affiliation');
                  if (reviewAffiliation) {
                    reviewAffiliation.textContent = affiliation.value;
                  }
                }

                if (rank) {
                  const reviewRank = document.getElementById('review-rank');
                  if (reviewRank) {
                    reviewRank.textContent = rank.value;
                  }
                }

                if (organization) {
                  const reviewOrg = document.getElementById('review-organization');
                  if (reviewOrg) {
                    reviewOrg.textContent = organization.value;
                  }
                }

                if (username) {
                  const reviewUsername = document.getElementById('review-username');
                  if (reviewUsername) {
                    reviewUsername.textContent = username.value;
                  }
                }

                /*if (notes) {
                  const reviewNotes = document.getElementById('review-notes');
                  if (reviewNotes) {
                    reviewNotes.textContent = notes.value;
                  }
                }*/

                // Extract DoD ID from CAC Identity if not already set
                const cacIdentityElement = document.querySelector('.cac-identity .review-value');
                const dodIdElement = document.getElementById('review-dodid');

                if (cacIdentityElement && dodIdElement && !dodIdElement.textContent.trim()) {
                  const cacIdentity = cacIdentityElement.textContent;
                  const parts = cacIdentity.split('.');
                  if (parts.length > 0) {
                    const lastPart = parts[parts.length - 1];
                    if (/^\d+$/.test(lastPart)) {
                      dodIdElement.textContent = lastPart;
                    }
                  }
                }
              };

              // Call the function to populate review data
              populateReviewData();

              // Rename the submit button and set the form action
              if (submitBtn) {
                submitBtn.value = "Submit & Continue";

                // Set the form action to the correct URL and location value
                const form = document.getElementById('baby-yoda-form');
                const locationInput = document.getElementById('user.attributes.location');

                if (locationInput) {
                  locationInput.value = '42';
                }

                if (form) {
                  form.setAttribute('action', '${url.registrationAction?no_esc}');
                }
              }

              console.log('CAC detected - skipped to step 4 and populated review data');
            }, 100);
          }
        }, true); // Use capturing to ensure this runs before the default handler
      }
    });

    // Script to control the visibility of the Caps Lock warning divs
    const topCapsLockWarning = document.getElementById('top-caps-lock-warning');
    const bottomCapsLockWarning = document.getElementById('bottom-caps-lock-warning');

    let capsLockActive = false;

    document.addEventListener('keydown', function (event) {
      if (event.getModifierState && event.getModifierState('CapsLock')) {
        capsLockActive = true;
        showCapsLockWarning();
      }
    });

    document.addEventListener('keyup', function (event) {
      if (!event.getModifierState || !event.getModifierState('CapsLock')) {
        capsLockActive = false;
        hideCapsLockWarning();
      }
    });

    function showCapsLockWarning() {
      topCapsLockWarning.style.display = 'block';
      bottomCapsLockWarning.style.display = 'block';
      topCapsLockWarning.style.fontSize = '40px';
      topCapsLockWarning.style.fontWeight = 'bold';
      bottomCapsLockWarning.style.fontSize = '40px';
      bottomCapsLockWarning.style.fontWeight = 'bold';
    }

    function hideCapsLockWarning() {
      if (!capsLockActive) {
        topCapsLockWarning.style.display = 'none';
        bottomCapsLockWarning.style.display = 'none';
      }
    }

    // Script to show and hide the password using a checkbox
    function togglePasswordVisibility(inputId) {
      const passwordInput = document.getElementById(inputId);

      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
      } else {
        passwordInput.type = 'password';
      }
    }

    // Event listeners added to the checkboxes
    document.addEventListener('DOMContentLoaded', function () {
      const showPasswordCheckbox = document.getElementById('show-password-checkbox');
      // const showConfirmPasswordCheckbox = document.getElementById('show-confirm-password-checkbox'); // Removed this checkbox
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('password-confirm');

      // Toggle visibility for BOTH password fields when the main checkbox is checked
      if (showPasswordCheckbox) {
        showPasswordCheckbox.addEventListener('change', function () {
          togglePasswordVisibility('password');
          // Only toggle confirm password visibility if it's currently shown
          const confirmPasswordGroup = document.getElementById('password-confirm-group');
          if (confirmPasswordGroup && confirmPasswordGroup.style.display !== 'none') {
            togglePasswordVisibility('password-confirm');
          }
        });
      }

      // Removed event listener for showConfirmPasswordCheckbox as the element is gone
    });

    // Script to update password requirements color and enable/disable the confirm password field
    // Removed hasRepeatingCharactersAnywhere function as it implemented the wrong rule

    function updatePasswordRequirements() {
      const credInput = document.getElementById('password');
      const confirmCredInput = document.getElementById('password-confirm');
      const confirmCredLabel = document.querySelector('label[for="password-confirm"]');
      // Removed references to non-existent 'show-confirm-password-checkbox'
      const credRequirements = document.getElementById('password-requirements');
      const credLength = document.getElementById('password-length');
      const credUppercase = document.getElementById('password-uppercase');
      const credLowercase = document.getElementById('password-lowercase');
      const credNumeric = document.getElementById('password-numeric');
      const credSpecial = document.getElementById('password-special');
      const credRepeating = document.getElementById('password-repeating');
      const cred = credInput.value;
      const confirmCred = confirmCredInput.value;

      // Password requirements
      const requirements = {
        length: cred.length >= 15,
        uppercase: /[A-Z]/.test(cred),
        lowercase: /[a-z]/.test(cred),
        numeric: /[0-9]/.test(cred),
        special: /[~!@#$%^&*()_+=\-'[\]\/?><]/.test(cred)
      };

      const specialCharCount = (cred.match(/[~!@#$%^&*()_+=\-'[\]\/?><]/g) || []).length;

      // Update the requirements classes instead of inline styles
      // Update the requirements classes: only add/remove 'text-error'
      // Update the requirements: remove/add 'text-error' and set/remove inline style for green
      function updateRequirementClass(element, isValid) {
        if (isValid) {
          element.classList.remove('text-error');
          element.style.color = 'var(--c-pacific-green)'; // Use theme's green variable
        } else {
          element.classList.add('text-error');
          element.style.color = ''; // Remove inline style so text-error class applies
        }
      }

      updateRequirementClass(credLength, requirements.length);
      updateRequirementClass(credUppercase, requirements.uppercase);
      updateRequirementClass(credLowercase, requirements.lowercase);
      updateRequirementClass(credNumeric, requirements.numeric);
      updateRequirementClass(credSpecial, specialCharCount >= 2);

      // Confirm password field is now always visible and enabled via HTML changes.
        // This section is no longer needed to control visibility/readonly state.
    }

    // Event listener for password input changes
    document.addEventListener('DOMContentLoaded', function() {
      const passwordInputEl = document.getElementById('password');
      const confirmPasswordInputEl = document.getElementById('password-confirm');
      const confirmPasswordGroup = document.getElementById('password-confirm-group');

      if (passwordInputEl) {
        passwordInputEl.addEventListener('input', function() {
          updatePasswordRequirements();
          
          // Show confirm password field when user starts typing in password field
          if (passwordInputEl.value.length > 0 && confirmPasswordGroup) {
            confirmPasswordGroup.style.display = 'block';
          } else if (passwordInputEl.value.length === 0 && confirmPasswordGroup) {
            confirmPasswordGroup.style.display = 'none';
            // Clear confirm password field when password is empty
            if (confirmPasswordInputEl) {
              confirmPasswordInputEl.value = '';
            }
          }
        });
      }
      if (confirmPasswordInputEl) {
        confirmPasswordInputEl.addEventListener('input', updatePasswordRequirements);
      }

      // Script for checking email mismatches and displaying the error message
      const emailInput = document.getElementById('email');
      const confirmEmailInput = document.getElementById('confirmEmail');
      const emailMismatchError = document.getElementById('email-mismatch-error');

      // Function to check for email mismatches
      function checkEmailMismatches() {
        const emailValue = emailInput.value.trim();
        const confirmEmailValue = confirmEmailInput.value.trim();

        if (emailValue !== confirmEmailValue) {
          emailMismatchError.style.display = 'block';
        } else {
          emailMismatchError.style.display = 'none';
        }
      }

      // Event listener to the confirm email field
      confirmEmailInput.addEventListener('blur', checkEmailMismatches);

      // Script for checking password mismatches and displaying the error message
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('password-confirm');
      const passwordMismatchError = document.getElementById('password-mismatch-error');
      const registerButton = document.getElementById('do-register');

      function checkPasswordMismatches() {
        const passwordValue = passwordInput.value.trim();
        const confirmPasswordValue = confirmPasswordInput.value.trim();
        const confirmPasswordGroup = document.getElementById('password-confirm-group');

        // Only check for mismatches if confirm password field is visible and has content
        if (confirmPasswordGroup && confirmPasswordGroup.style.display !== 'none') {
          if (passwordValue !== confirmPasswordValue) {
            passwordMismatchError.style.display = 'block';
            if (registerButton) registerButton.disabled = true;
          } else {
            passwordMismatchError.style.display = 'none';
            if (registerButton) registerButton.disabled = false;
          }
        } else {
          // Hide mismatch error if confirm field is not visible
          passwordMismatchError.style.display = 'none';
          if (registerButton) registerButton.disabled = false;
        }
      }

      if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('keyup', checkPasswordMismatches);
      }
      if (passwordInput) {
        passwordInput.addEventListener('keyup', checkPasswordMismatches);
      }

      // --- UID Toggle and Validation Logic ---
      const toggleUidCheckbox = document.getElementById('toggle-uid');
      const uidSection = document.getElementById('uid-section');
      const uidInput = document.getElementById('user.attributes.uid');
      const uidFormatError = document.getElementById('uid-format-error');

      if (toggleUidCheckbox && uidSection && uidInput && uidFormatError) {
        // Show/hide UID section based on toggle
        toggleUidCheckbox.addEventListener('change', function() {
          if (this.checked) {
            uidSection.style.display = 'block';
            uidInput.required = true; // Make required when shown
          } else {
            uidSection.style.display = 'none';
            uidInput.required = false; // Make not required when hidden
            uidInput.value = ''; // Clear value when hidden
            uidFormatError.style.display = 'none'; // Hide error message
            // Optional: Remove any server-side error message display if needed
            const uidErrorSpan = uidSection.querySelector('.message-details');
            if (uidErrorSpan) {
              uidErrorSpan.textContent = '';
              uidSection.classList.remove('has-error');
            }
          }
        });

        // Input masking and validation for UID (123-456-789)
        uidInput.addEventListener('input', function(e) {
          let value = e.target.value.replace(/\D/g, ''); // Remove non-digits
          let formattedValue = '';

          if (value.length > 0) {
            formattedValue = value.substring(0, 3);
          }
          if (value.length > 3) {
            formattedValue += '-' + value.substring(3, 6);
          }
          if (value.length > 6) {
            formattedValue += '-' + value.substring(6, 9);
          }

          e.target.value = formattedValue;

          // Basic format validation on input
          const pattern = /^\d{3}-\d{3}-\d{3}$/;
          if (formattedValue.length > 0 && !pattern.test(formattedValue)) {
            // Show error only if partially filled and incorrect, or fully filled and incorrect
            if (formattedValue.length === 11 || (formattedValue.length < 11 && formattedValue.includes('-'))) {
              uidFormatError.style.display = 'block';
            } else {
              uidFormatError.style.display = 'none';
            }
          } else {
            uidFormatError.style.display = 'none';
          }
        });

        // Final validation check on blur (optional, but good practice)
        uidInput.addEventListener('blur', function(e) {
          const pattern = /^\d{3}-\d{3}-\d{3}$/;
          if (e.target.value.length > 0 && !pattern.test(e.target.value)) {
            uidFormatError.style.display = 'block';
          } else {
            uidFormatError.style.display = 'none';
          }
        });
      }
      // --- End UID Logic ---

    });
  </script>

</#if>
