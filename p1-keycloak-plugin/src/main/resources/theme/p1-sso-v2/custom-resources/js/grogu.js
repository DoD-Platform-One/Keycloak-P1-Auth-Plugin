

globalThis.addEventListener("DOMContentLoaded", () => {
  const nav = document.getElementById("navbar");
  const icon = document.getElementById("hamburger");

  if (nav && icon) {
    // Toggle mobile class on resize
    function updateNavMode() {
      if (globalThis.innerWidth < 1100) {
        nav.classList.add('mobile');
        icon.classList.add('mobile');
      } else {
        nav.classList.remove('mobile', 'open');
        icon.classList.remove('mobile');
      }
    }

    globalThis.addEventListener("resize", updateNavMode);
    updateNavMode()

    // Hamburger click toggles open class
    icon.addEventListener("click", () => {
      if (nav.classList.contains('mobile')) {
        nav.classList.toggle('open');
      }
    });
  }
});

// Scripts for registration

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('multi-step-form');
  if (form) {
    let currentStep = 0; // Always start at step 0 (Prerequisites page)

    // --- Check for server error on page load ---
    // Note: The actual error detection is now handled in register.ftl
    // where FreeMarker variables are available. This is just a fallback.
    // Check if currentStep was already set by register.ftl
    if (globalThis.currentStep !== undefined && globalThis.currentStep !== null) {
      currentStep = globalThis.currentStep;
      console.log("Using currentStep from register.ftl:", currentStep);
    }
    // --- End server error check ---
    const totalSteps = 3;

    const stepInput = document.getElementById('step');
    const steps = document.querySelectorAll('.step-content');
    const prevBtn = document.getElementById('prev-step');
    const nextBtn = document.getElementById('next-step');
    const submitBtn = document.getElementById('submit-form');

    function showStep(step) {
      for (const s of steps) {
        s.classList.toggle('hidden', Number.parseInt(s.dataset.step) !== step);
      }

      if (stepInput) {
        stepInput.value = step;
      }

      if (prevBtn) {
        // Always show Back button except on step 0
        prevBtn.classList.toggle('hidden', step === 0);
      }

      if (nextBtn) {
        // Show Next button on steps 0-1, hide on step 2
        nextBtn.classList.toggle('hidden', step >= 2);
      }

      if (submitBtn) {
        // Show Submit button only on step 2
        submitBtn.classList.toggle('hidden', step !== 2);
      }

      // Populate review data when reaching step 2
      if (step === 2) {
        setTimeout(() => {
          populateReviewData();
          if (submitBtn) {
            submitBtn.value = "Submit & Continue";
          }
        }, 50);
      }
    }

    // Helper function to populate a single review field
    function populateReviewField(sourceId, targetId, getValue) {
      const sourceElement = document.getElementById(sourceId);
      const targetElement = document.getElementById(targetId);
      
      if (sourceElement && targetElement) {
        targetElement.textContent = getValue ? getValue(sourceElement) : sourceElement.value;
      }
    }
    
    // Helper function to populate name field
    function populateNameField() {
      const firstName = document.getElementById('firstName');
      const lastName = document.getElementById('lastName');
      const reviewName = document.getElementById('review-name');
      
      if (firstName && lastName && reviewName) {
        reviewName.textContent = firstName.value + ' ' + lastName.value;
      }
    }
    
    // Helper function to extract and populate DoD ID
    function populateDodId() {
      const cacIdentityElement = document.querySelector('.cac-identity .table-value');
      const dodIdElement = document.getElementById('review-dodid');
      
      if (!cacIdentityElement || !dodIdElement || dodIdElement.textContent.trim()) {
        return;
      }
      
      const cacIdentity = cacIdentityElement.textContent;
      const parts = cacIdentity.split('.');
      
      if (parts.length === 0) return;
      
      const lastPart = parts.at(-1);
      if (/^\d+$/.test(lastPart)) {
        dodIdElement.textContent = lastPart;
      }
    }
    
    // Function to populate review data
    function populateReviewData() {
      // Define field mappings
      const fieldMappings = [
        { source: 'email', target: 'review-email' },
        { source: 'user.attributes.affiliation', target: 'review-affiliation' },
        { source: 'user.attributes.rank', target: 'review-rank' },
        { source: 'user.attributes.organization', target: 'review-organization' },
        { source: 'username', target: 'review-username' },
        { source: 'user.attributes.notes', target: 'review-notes' }
      ];
      
      // Populate simple fields
      for (const mapping of fieldMappings) {
        populateReviewField(mapping.source, mapping.target);
      }
      
      // Populate composite fields
      populateNameField();
      populateDodId();
    }

    if (prevBtn) {
      prevBtn.addEventListener('click', () => {
        if (currentStep > 0) {
          currentStep--;
          showStep(currentStep);
          globalThis.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
        }
      });
    }

    // --- Validation Helper Functions ---
    
    // Create error span element
    function createErrorSpan(errorSpanId, field, formGroup) {
      const errorSpan = document.createElement('span');
      errorSpan.id = errorSpanId;
      errorSpan.className = 'message-details text-error';
      errorSpan.style.display = 'none';
      errorSpan.setAttribute('aria-live', 'polite');
      
      if (field?.parentNode) {
        field.parentNode.insertBefore(errorSpan, field.nextSibling);
      } else if (formGroup) {
        formGroup.appendChild(errorSpan);
      }
      return errorSpan;
    }
    
    // Toggle error display
    function toggleFieldError(fieldId, showError, message = 'This field is required.') {
      const field = document.getElementById(fieldId);
      const errorSpanId = fieldId + '-error';
      let errorSpan = document.getElementById(errorSpanId);
      const formGroup = field?.closest('.form-group');
      
      if (!errorSpan && formGroup) {
        errorSpan = createErrorSpan(errorSpanId, field, formGroup);
      }
      
      if (errorSpan) {
        errorSpan.textContent = message;
        errorSpan.style.display = showError ? 'block' : 'none';
      }
      
      if (formGroup) {
        formGroup.classList.toggle('has-error', showError);
      }
      
      return showError;
    }
    
    // Validate text field
    function validateTextField(fieldId, errorMsg) {
      const field = document.getElementById(fieldId);
      return toggleFieldError(fieldId, !field?.value.trim(), errorMsg);
    }
    
    // Validate select field
    function validateSelectField(fieldId, errorMsg) {
      const field = document.getElementById(fieldId);
      const isInvalid = !field?.value || field.selectedIndex === 0;
      return toggleFieldError(fieldId, isInvalid, errorMsg);
    }
    
    // Validate email format
    function validateEmailField(fieldId) {
      const field = document.getElementById(fieldId);
      const value = field?.value.trim();
      // Simplified regex that avoids backtracking issues
      // Limits each part to reasonable lengths to prevent ReDoS
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      
      if (!value) {
        return toggleFieldError(fieldId, true);
      }
      // Additional length check to prevent excessive input
      if (value.length > 254) {
        return toggleFieldError(fieldId, true, 'Email address is too long.');
      }
      if (!emailRegex.test(value)) {
        return toggleFieldError(fieldId, true, 'Please enter a valid email address.');
      }
      return toggleFieldError(fieldId, false);
    }
    
    // Handle mismatch error display
    function handleMismatchError(fieldId, mismatchDivId, show, message) {
      const field = document.getElementById(fieldId);
      const mismatchDiv = document.getElementById(mismatchDivId);
      const formGroup = field?.closest('.form-group');
      
      if (mismatchDiv) {
        mismatchDiv.style.display = show ? 'block' : 'none';
        if (formGroup) {
          formGroup.classList.toggle('has-error', show);
        }
        return show;
      }
      
      return toggleFieldError(fieldId, show, message);
    }
    
    // Validate matching fields
    function validateMatchingFields(field1Id, field2Id, mismatchDivId, errorMsg) {
      const field1 = document.getElementById(field1Id);
      const field2 = document.getElementById(field2Id);
      const value1 = field1?.value.trim();
      const value2 = field2?.value.trim();
      
      if (!value2) {
        return toggleFieldError(field2Id, true);
      }
      
      const hasError = value1 && value1 !== value2;
      return handleMismatchError(field2Id, mismatchDivId, hasError, errorMsg);
    }
    
    // Check password requirements
    function checkPasswordRequirements(password) {
      const requirements = {
        length: password && password.length >= 15,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        numeric: /\d/.test(password),
        special: (password?.match(/[~!@#$%^&*()_+=\-'[\]/?><]/g) || []).length >= 2,
        repeating: password && !/(.)\1+/.test(password),
      };
      return Object.values(requirements).every(Boolean);
    }
    
    // Validate password field
    function validatePasswordField() {
      const password = document.getElementById('password');
      const passwordValue = password?.value;
      
      if (!passwordValue) {
        return toggleFieldError('password', true);
      }
      
      const meetsRequirements = checkPasswordRequirements(passwordValue);
      if (!meetsRequirements) {
        return toggleFieldError('password', true, 'Password does not meet all requirements.');
      }
      
      return toggleFieldError('password', false);
    }
    
    // Validate password confirmation
    function validatePasswordConfirm() {
      const password = document.getElementById('password');
      const passwordConfirm = document.getElementById('password-confirm');
      const passwordValue = password?.value;
      const confirmValue = passwordConfirm?.value;
      
      if (!confirmValue) {
        return toggleFieldError('password-confirm', true);
      }
      
      const hasError = passwordValue !== confirmValue;
      return handleMismatchError('password-confirm', 'password-mismatch-error', hasError, 'Passwords do not match.');
    }
    
    // --- Main Validation Function for Step 2 ---
    function validateStep2() {
      const isCacUser = `<#if cacIdentity??>true<#else>false</#if>`;
      let hasErrors = false;
      
      // Validate text fields
      hasErrors |= validateTextField('firstName');
      hasErrors |= validateTextField('lastName');
      hasErrors |= validateTextField('user.attributes.organization');
      
      // Validate select fields
      hasErrors |= validateSelectField('user.attributes.affiliation', 'Please select an affiliation.');
      hasErrors |= validateSelectField('user.attributes.rank', 'Please select a pay grade.');
      
      // Validate email fields
      hasErrors |= validateEmailField('email');
      hasErrors |= validateMatchingFields('email', 'confirmEmail', 'email-mismatch-error', 'Email addresses do not match.');
      
      // Validate username if present
      const username = document.getElementById('username');
      if (username) {
        hasErrors |= validateTextField('username');
      }
      
      // Validate persona field if it has a value (optional field)
      const personaField = document.getElementById('user.attributes.persona');
      if (personaField?.value.trim()) {
        const personaPattern = /^\d{3}-[A-Z]{2,10}-[a-z]+$/;
        const personaValue = personaField.value.trim();
        const personaWarning = document.getElementById('persona-format-warning');
        
        if (!personaPattern.test(personaValue)) {
          if (personaWarning) {
            personaWarning.style.display = 'block';
          }
          // Don't set hasErrors since it's optional, just show warning
        } else if (personaWarning) {
          personaWarning.style.display = 'none';
        }
      }
      
      // Validate password fields if not CAC user
      if (!isCacUser) {
        hasErrors |= validatePasswordField();
        
        // Only validate confirm if password is valid
        const passwordHasError = toggleFieldError('password', false) === false;
        if (!passwordHasError) {
          hasErrors |= validatePasswordConfirm();
        }
      }
      
      return !hasErrors;
    }
    // --- End Validation Functions ---

    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        if (currentStep < totalSteps) {
          // --- Add Validation Call ---
          if (currentStep === 1) { // Only validate when leaving step 1 (going to step 2 - review)
            if (!validateStep2()) {
              console.log("Step 1 validation failed - cannot proceed to review.");
              return; // Stop if validation fails - no scroll
            }
            console.log("Step 1 validation passed - proceeding to review.");
          }
          // --- End Validation Call ---

          currentStep++;
          showStep(currentStep);
          // Only scroll to top when successfully moving to a new step
          globalThis.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
        }
      });
    }

    // Add event listener for the Submit & Continue button
    if (submitBtn) {
      submitBtn.addEventListener('click', (e) => {
        e.preventDefault(); // Prevent default behavior
        // Make sure the location field is set
        const locationInput = document.getElementById('user.attributes.location');
        if (locationInput) { // Always set the value if the input exists
          locationInput.value = '42';
        }


        // Remove ALL hidden inputs before submitting to prevent saving them as attributes
        const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
        for (const input of hiddenInputs) {
          console.log('Removing hidden input:', input.name); // Optional: for debugging
          input.remove();
        }

        // Explicitly submit the form
        form.submit();
      });
    }

    showStep(currentStep); // Initial render
    
    // Add real-time validation for persona field
    const personaInput = document.getElementById('user.attributes.persona');
    const personaFormatWarning = document.getElementById('persona-format-warning');
    
    if (personaInput && personaFormatWarning) {
      personaInput.addEventListener('input', function(e) {
        const value = e.target.value.trim();
        const pattern = /^\d{3}-[A-Z]{2,10}-[a-z]+$/;
        
        // Only show warning if there's text and it doesn't match the pattern
        if (value.length > 0 && !pattern.test(value)) {
          personaFormatWarning.style.display = 'block';
        } else {
          personaFormatWarning.style.display = 'none';
        }
      });
    }
  }
});
