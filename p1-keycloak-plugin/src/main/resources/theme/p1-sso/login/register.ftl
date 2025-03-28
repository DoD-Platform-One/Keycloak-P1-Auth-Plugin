<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('firstName','lastName','email','username','password','password-confirm','confirmEmail', 'cacIdentity'); section>
    <#if section = "form">
        <form action="/chuck-norris-calendar-goes-straight-from-march-31st-to-april-2nd-because-no-one-fools-chuck-norris"
              id="baby-yoda-form" method="post">

            <#if cacIdentity??>
                <div class="alert alert-info cac-info">
                    <h2>DoD PKI User Registration</h2>
                    <p>${cacIdentity}</p>
                </div>
            <#else>
                <div class="alert alert-info cac-info">
                    <h2>Regular User Registration</h2>
                    <p>Use your company or government email address as your access will be based off of your validated email address.</p>
                    <p class="font-weight-bold">For assistance contact your team admin, <a
                                href="https://sso-info.il2.dso.mil/" target="_blank">click here</a> or <a id="helpdesk"
                                                                                                          href="mailto:help@dsop.io">email us</a>.
                    </p>
                </div>
            </#if>

            <div id="top-caps-lock-warning" style="color: red; display: none; text-align: center;">
            Warning: Caps Lock is On
            </div>

            <div class="row">

                <div class="col-lg-6 form-group ${messagesPerField.printIfExists('firstName','has-error')}">
                    <label for="firstName" class="form-label">${msg("firstName")}</label>
                    <input type="text" id="firstName" class="form-control" name="firstName"
                           value="${(register.formData.firstName!'')}"/>
                    <#if messagesPerField.existsError('firstName')>
                        <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('firstName'))?no_esc}</span>
                    </#if>
                </div>

                <div class="col-lg-6 form-group ${messagesPerField.printIfExists('lastName','has-error')}">
                    <label for="lastName" class="form-label">${msg("lastName")}</label>
                    <input type="text" id="lastName" class="form-control" name="lastName"
                            value="${(register.formData.lastName!'')}"/>
                    <#if messagesPerField.existsError('lastName')>
                        <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('lastName'))?no_esc}</span>
                    </#if>
                </div>

            </div>

            <div class="row">

                <div class="col-lg-6 form-group ${messagesPerField.printIfExists('user.attributes.affiliation','has-error')}">
                    <label for="user.attributes.affiliation" class="form-label">Affiliation</label>
                    <select id="user.attributes.affiliation" name="user.attributes.affiliation" class="form-control">
                        <option selected disabled hidden>Select your org</option>
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
                    <#if messagesPerField.existsError('user.attributes.affiliation')>
                        <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('user.attributes.affiliation'))?no_esc}</span>
                    </#if>
                </div>

                <div class="col-lg-6 form-group ${messagesPerField.printIfExists('user.attributes.rank','has-error')}">
                    <label for="user.attributes.rank" class="form-label">Pay Grade</label>
                    <select id="user.attributes.rank" name="user.attributes.rank" class="form-control">
                        <option selected disabled hidden>Select your rank</option>
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
                    <#if messagesPerField.existsError('user.attributes.rank')>
                        <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('user.attributes.rank'))?no_esc}</span>
                    </#if>
                </div>

            </div>

            <div class="form-group ${messagesPerField.printIfExists('user.attributes.organization','has-error')}">
                <label for="user.attributes.organization" class="form-label">Unit, Organization or Company Name</label>
                <input id="user.attributes.organization" class="form-control" name="user.attributes.organization" type="text"
                        value="${(register.formData['user.attributes.organization']!'')}" autocomplete="company"/>
                <#if messagesPerField.existsError('user.attributes.organization')>
                    <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('user.attributes.organization'))?no_esc}</span>
                </#if>
            </div>
            <div class="location-input">
                <div class="form-group">
                    <label for="user.attributes.location" class="form-label">Location</label>
                    <input id="user.attributes.location" class="form-control" name="user.attributes.location" tabindex="-1 type="text" />
                </div>
            </div>

            <#if !realm.registrationEmailAsUsername>
                <div class="form-group ${messagesPerField.printIfExists('username','has-error')}">
                    <label for="username" class="form-label">${msg("username")}</label>
                    <input id="username" class="form-control" name="username" type="text"
                            value="${(register.formData.username!'')}" autocomplete="username"/>
                    <#if messagesPerField.existsError('username')>
                        <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('username'))?no_esc}</span>
                    </#if>
                </div>
            </#if>

            <div class="form-group ${messagesPerField.printIfExists('email','has-error')}">
                <label for="email" class="form-label">${msg("email")}</label>
                <input id="email" class="form-control" name="email" type="text"
                        value="${(register.formData.email!'')}" autocomplete="email"/>
                <#if messagesPerField.existsError('email')>
                    <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('email'))?no_esc}</span>
                </#if>
                <br>
            </div>

            <div class="form-group">
                <label for="confirmEmail" class="form-label">Confirm email</label>
                <input id="confirmEmail" class="form-control" name="confirmEmail" type="text" value="${(register.formData.confirmEmail!'')}" autocomplete="email"/>
                <#if messagesPerField.existsError('confirmEmail')>
                    <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('confirmEmail'))?no_esc}</span>
                </#if>
                <br>
                <span id="email-mismatch-error" style="color: red; display: none;">Error: Emails Don't Match</span>
            </div>
            <div class="form-group ${messagesPerField.printIfExists('notes','has-error')}">
                <label for="user.attributes.notes" class="form-label ">${msg("accessRequest")}</label>
                <textarea id="user.attributes.notes" class="form-control " name="user.attributes.notes"></textarea>
            </div>

            <div class="form-group ${messagesPerField.printIfExists('password','has-error')}">
                <#if cacIdentity??>
                    <div class="alert alert-info cac-info text-white">
                        ${msg("passwordCacMessage1")}
                        <span class="note-important">${msg("passwordCacMessage2")}</span>
                        ${msg("passwordCacMessage3")}
                    </div>
                    <label for="password" class="form-label ">${msg("passwordOptional")}</label>
                <#else>
                    <label for="password" class="form-label ">${msg("password")}</label>
                </#if>
                <input id="password" class="form-control " name="password"
                        type="password" autocomplete="new-password"/>
                <#if messagesPerField.existsError('password')>
                    <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('password'))?no_esc}</span>
                </#if>
            </div>

            <div class="form-group">
                <label>Show Password</label>
                <input type="checkbox" id="show-password-checkbox">
            </div>

            <div class="form-group" style="color: white;">
                <label>Password Requirements</label>
                <ul id="password-requirements">
                    <li id="password-length" style="color: red;">15 Character Minimum</li>
                    <li id="password-uppercase" style="color: red;">1 Uppercase Letter</li>
                    <li id="password-lowercase" style="color: red;">1 Lowercase Letter</li>
                    <li id="password-numeric" style="color: red;">1 Numeric Character</li>
                    <li id="password-special" style="color: red;">2 Special Characters: [~!@#$%^&*()_+=\-‘[\]\/?><]</li>
                    <li id="password-repeating" style="color: red;">No Repeating Characters</li>
                </ul>
            </div>
            <div class="form-group ${messagesPerField.printIfExists('password-confirm','has-error')}">
                <label for="password-confirm" class="form-label" style="display: none;">${msg("passwordConfirm")}</label>
                <input id="password-confirm" class="form-control " name="password-confirm" style="display:none;"
                        type="password" autocomplete="new-password" readonly />
                <#if messagesPerField.existsError('password-confirm')>
                    <span class="message-details" aria-live="polite">${kcSanitize(messagesPerField.get('password-confirm'))?no_esc}</span>
                </#if>
                <br>
                <span id="password-mismatch-error" style="color: red; display: none;">Error: Passwords Don't Match</span>
            </div>

             <div class="form-group">
                <label for="show-confirm-password-checkbox" style="display:none;">Show Password</label>
                <input type="checkbox" id="show-confirm-password-checkbox" style="display:none;">
            </div>
            <#if recaptchaRequired??>
                <div class="form-group">
                    <div>
                        <div class="g-recaptcha" data-theme="dark" data-size="normal"
                             data-sitekey="${recaptchaSiteKey}"></div>
                    </div>
                </div>
            </#if>

            <div id="bottom-caps-lock-warning" style="color: red; display: none; text-align: center;">
            Warning: Caps Lock is On
            </div>

            <div class="form-group">
                <div id="kc-form-buttons">
                    <input id="do-register" disabled="disabled"
                           class="btn btn-primary btn-block"
                           type="submit" value="${msg("doRegister")}"/>
                </div>
            </div>

        </form>

        <div class="footer-text" id="footer-text">
            Already registered? <a href="/auth">Click here</a> to login now.<br>
            You must be a human to register, confidence is increased as you interact with this page.
            <br><br>
            <a>Currently only <span id="confidence">1</span>% convinced you're not a robot.</a>
        </div>

    </#if>
</@layout.registrationLayout>

<script>
    document.getElementById('user.attributes.affiliation').value = "${(register.formData['user.attributes.affiliation']!'')}";
    document.getElementById('user.attributes.rank').value = "${(register.formData['user.attributes.rank']!'')}";

    (function () {
        const threshold = 250;
        let count = 0;
        let complete = false;

        window.onload = tracker;
        window.onmousemove = tracker;
        window.onmousedown = tracker;
        window.ontouchstart = tracker;
        window.onclick = tracker;
        window.onkeypress = tracker;
        window.addEventListener('scroll', tracker, true);

        const confidence = document.getElementById('confidence');

        function tracker() {
            if (complete) {
                return;
            }

            count++;
            confidence.innerText = Math.round((count / threshold) * 100);

            if (count > threshold) {
                complete = true;

                const form = document.getElementById('baby-yoda-form');
                const register = document.getElementById('do-register');
                const location = document.getElementById('user.attributes.location');

                location.value = '42';

                form.setAttribute('action', '${url.registrationAction?no_esc}');
                register.removeAttribute('disabled');
            }
        }
    }());
</script>

<script>
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
</script>

<script>
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
        const showConfirmPasswordCheckbox = document.getElementById('show-confirm-password-checkbox');
        const passwordInput = document.getElementById('password');
        const confirmPasswordInput = document.getElementById('password-confirm');

        // Toggle password visibility when the "Show Password" checkbox is checked
        showPasswordCheckbox.addEventListener('change', function () {
            togglePasswordVisibility('password');
        });

        // Toggle confirm password visibility when the "Show Password" checkbox is checked
        showConfirmPasswordCheckbox.addEventListener('change', function () {
            togglePasswordVisibility('password-confirm');
        });
    });
</script>

<script>
    // Script to update password requirements color and enable/disable the confirm password field
    function updatePasswordRequirements() {
        const credInput = document.getElementById('password');
        const confirmCredInput = document.getElementById('password-confirm');
        const confirmCredLabel = confirmCredInput.labels[0] //document.getElementById('password-confirm-label');
        const showConfirmCredCheckbox = document.getElementById('show-confirm-password-checkbox');
        const showConfirmCredCheckboxLabel = showConfirmCredCheckbox.labels[0]
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
            special: /[~!@#$%^&*()_+=\-‘[\]\/?><]/.test(cred),
            repeating: !/(.)\1{1,}/.test(cred),
        };

        const specialCharCount = (cred.match(/[~!@#$%^&*()_+=\-‘[\]\/?><]/g) || []).length;

        // Update the requirements color and special character check
        credLength.style.color = requirements.length ? 'green' : 'red';
        credUppercase.style.color = requirements.uppercase ? 'green' : 'red';
        credLowercase.style.color = requirements.lowercase ? 'green' : 'red';
        credNumeric.style.color = requirements.numeric ? 'green' : 'red';
        credSpecial.style.color = specialCharCount >= 2 ? 'green' : 'red';
        credRepeating.style.color = requirements.repeating ? 'green' : 'red';

        // Check if all requirements are green
        //const allColorsGreen = Object.values(requirements).every(color => color === 'green');
        const allColorsGreen = Object.values(requirements).every(test => test === true);
        const isConfirmCredEnabled = allColorsGreen;
       if (isConfirmCredEnabled) {
            confirmCredLabel.style.display = 'block';
            confirmCredInput.style.display = 'block';
            confirmCredInput.removeAttribute('readonly')
            showConfirmCredCheckbox.style.display = 'inline'
            showConfirmCredCheckboxLabel.style.display = 'inline';
        } else {
            confirmCredLabel.style.display = 'none';
            confirmCredInput.style.display = 'none';
            showConfirmCredCheckbox.style.display = 'none';
            showConfirmCredCheckboxLabel.style.display = 'none';
            confirmCredInput.value = '';
        }
    }

    // Event listener for password input changes
    document.getElementById('password').addEventListener('input', updatePasswordRequirements);
    document.getElementById('password-confirm').addEventListener('input', updatePasswordRequirements);
</script>

<script>
    // Script for checking email mismatches and displaying the error message
        document.addEventListener('DOMContentLoaded', function () {
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
    });
</script>

<script>
    // Script for checking passowrd mismatches and displaying the error message
    document.addEventListener('DOMContentLoaded', function () {
        const passwordInput = document.getElementById('password');
        const confirmPasswordInput = document.getElementById('password-confirm');
        const passwordMismatchError = document.getElementById('password-mismatch-error');
        const registerButton = document.getElementById('do-register');

        function checkPasswordMismatches() {
            const passwordValue = passwordInput.value.trim();
            const confirmPasswordValue = confirmPasswordInput.value.trim();

            if (passwordValue !== confirmPasswordValue) {
                passwordMismatchError.style.display = 'block';
                 registerButton.disabled = true;
            } else {
                passwordMismatchError.style.display = 'none';
                 registerButton.disabled = false;
            }
        }

        confirmPasswordInput.addEventListener('keyup', checkPasswordMismatches);
        passwordInput.addEventListener('keyup', checkPasswordMismatches);
    });
</script>

