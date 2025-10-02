<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
<div id="kc-faq-content">
  <h1>Frequently Answered Questions</h1>
  <div class="faq-section">

    <h2>Registration & SSO FAQ</h2>
    <div class="faq-item">
      <h3 class="faq-title">What is Platform One SSO?</h3>
      <div class="faq-answer">
        <p>Platform One SSO is a single sign-on service that allows you to access multiple applications with a single set of credentials.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">How do I register for an account?</h3>
      <div class="faq-answer">
        <p>You can register for an account by clicking on the "Register" link on the login page and following the instructions.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">What if I forget my password?</h3>
      <div class="faq-answer">
        <p>If you forget your password, you can click on the "Forgot Password" link on the login page to reset it.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">How do I use my CAC/PIV for authentication?</h3>
      <div class="faq-answer">
        <p>You can use your CAC/PIV for authentication by selecting the certificate option during login.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">How do I update my profile?</h3>
      <div class="faq-answer">
        <p>Log in to your account at which will bring you to your account settings page where you will be able to update your profile.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I have multiple Mattermost and/or P1 SSO accounts, can I combine them?</h3>
      <div class="faq-answer">
        <p>Unfortunately, there is no way for us to combine accounts. We can deactivate whichever account you will no longer be using. Let your team admin know which account (email address) you will no longer be using or email us directly at <a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a>.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">Where can I get more information on using Mattermost?</h3>
      <div class="faq-answer">
        <p>Check out <a href="https://docs.mattermost.com/help/getting-started/welcome-to-mattermost.html" target="_blank" rel="noopener noreferrer"> Mattermost's official user guide</a> for more information and best practices.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">Who do I contact for help?</h3>
      <div class="faq-answer">
        <p>If you need assistance, please contact the Platform One support team at <a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a>.</p>
      </div>
    </div>


    <h2>MFA Troubleshooting</h2>

    <div class="faq-item">
      <h3 class="faq-title">When setting up MFA, why do I keep getting "Invalid authenticator code"?</h3>
      <div class="faq-answer">
        <ul>
          <li>Ensure you are scanning the QR code with the MFA app on your mobile device or used the provided code. This will produce a MFA token (6-digit number) that changes every 30 seconds. Type in that 6-digit number (e.g. 123456) with no spaces.</li>
          <li>If the MFA token is not accepted, you will receive the "Invalid authenticator code" error. You must re-scan the QR code again which creates another MFA token (another 6-digit pin that is changing every 30 seconds). You must use the new 6-digit pin (you can delete the old ones).</li>
          <li>Your phone time may be out of sync. Check your phone's settings to make sure the time is updating automatically. If you're using Google Authenticator on Android, try the Sync Now feature to update the time.</li>
        </ul>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I created an account using a CAC but didn't set up a password. How do I set it up now?</h3>
      <div class="faq-answer">
        <p>Log in to your account at to access your profile. From here, click the "Password" tab to set a password. You will also need to click the "Authenticator" tab to set up multi-factor authentication (MFA).</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">Why am I not receiving a password reset email from P1 SSO?</h3>
      <div class="faq-answer">
        <ul>
          <li>Ensure you are scanning the QR code with the MFA app on your mobile device or used the provided code. This will produce a MFA token (6-digit number) that changes every 30 seconds. Type in that 6-digit number (e.g. 123456) with no spaces.</li>
          <li>If you accidently tried logging in using your old Mattermost credentials more than five times, your account is likely locked out. Contact a team admin or email us at <a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a> to have your account unlocked.</li>
        </ul>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">My account says it's disabled or receiving an X509 certification error</h3>
      <div class="faq-answer">
        <p>Send an email to <a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a> from the email address associated to your account. Include the word "disabled", "reactivate", or "unlock" in the body. Your account will be automatically unlocked and you will receive an email reply when once complete.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I've lost or upgraded my phone, so I can't log into my account to reset MFA.</h3>
      <div class="faq-answer">
        <ul>
          <li>Ensure you are scanning the QR code with the MFA app on your mobile device or used the provided code. This will produce a MFA token (6-digit number) that changes every 30 seconds. Type in that 6-digit number (e.g. 123456) with no spaces.</li>
        <li>If you don't have CAC access, email us at <a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a> from an approved email address (e.g. @us.af.mil) to request an MFA reset.</li>
        </ul>
      </div>
    </div>

  </div>

  <div class="back-link">
    <a href="${url.loginUrl}" class="btn btn-primary outline">Return to Login</a>
  </div>
</div>
</@layout.registrationLayout>

<script>
  let acc = document.getElementsByClassName("faq-title");
  let i;

  for (i = 0; i < acc.length; i++) {
    acc[i].addEventListener("click", function() {
      this.classList.toggle("active");
      let panel = this.nextElementSibling;
      if (panel.style.maxHeight) {
        panel.style.maxHeight = null;
      } else {
        panel.style.maxHeight = panel.scrollHeight + "px";
      }
    });
  }
</script>
