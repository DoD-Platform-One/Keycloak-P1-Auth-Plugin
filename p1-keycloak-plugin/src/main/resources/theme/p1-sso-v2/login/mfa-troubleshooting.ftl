<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
<div id="kc-faq-content">

  <h1>MFA Troubleshooting</h1>
  <p>The most common issue users have is the "Invalid authenticator code" error. Performing the following steps should resolve the issue.</p>
  <ol>
    <li class="text-lg">Check device time.</li>
    <ul>
      <li>For Apple iOS users, open Settings and go to General > Date & Time and make sure "Set Automatically" is enabled (green).<br>
        <picture>
          <source srcset="${url.resourcesPath}/img/troubleshooting_mfa_time_ios.webp">
          <img srcset="${url.resourcesPath}/img/troubleshooting_mfa_time_ios.webp" alt="Set time on iOS" width="400">
        </picture>
      </li>
      <li>For Android users, open Settings and go to System > Date & Time and make sure Use network-provided time is enabled (blue). Additionally, Android users can open the Google Authenticator app and tap the more icon (three vertical dots), select Settings > Time correction for codes and click "Sync now".</li>
      <picture>
        <source srcset="${url.resourcesPath}/img/troubleshooting_mfa_time_android.webp">
        <img srcset="${url.resourcesPath}/img/troubleshooting_mfa_time_android.webp" alt="Set time on Android" width="400">
      </picture>
    </ul>
    <li class="text-lg">Step 2: Rescan QR code</li>
    <p>Each time you attempt to enter the six digit code and it fails, the QR code is changed. You must rescan the QR code again and use the newly created six digit code that changes every 30 seconds. You can delete the previous MFA six digit code.</p>
      <picture>
        <source srcset="${url.resourcesPath}/img/troubleshooting_mfa_app.webp">
        <img srcset="${url.resourcesPath}/img/troubleshooting_mfa_app.webp" alt="Set time on Android" width="400">
      </picture>
    <li class="text-lg">Step 3: Enter the new code</li>
    <p>Enter the newely generted six digit code but make sure it's being typed in with no spaces (e.g. 123456). There should not be a space in the middile as displayed in the MFA app. If you receive another "Invalid authenticator code", you must rescan the QR code again which will create yet another six digit code.</p>
  </ol>
  <hr>
  <h2>Reset MFA</h2>
  <p>During account setup, there is a possibility you may end up with multiple MFA tokens set up on your account when you only intended to have one.</p>
  <p>Fortunately, there's an easy fix for this which is simply removing the MFA token you don't use or deleting all of them and setting up a new one. There may also be other reasons why you need to reset MFA, such as upgrading to a new phone or if you accidently deleted your existing MFA token.</p>
  <h3>Reset Steps</h3>
  <ol>
    <li>Log in to your account at and click the "Authenticator" tab.</li>
    <li>Click the trash can icons next to the MFA tokens listed for your account.</li>
    <li>You will then have the ability to set up MFA again. You can also delete any existing MFA tokens you have on your MFA mobile app.</li>
  </ol>
  <h3>Common Issues</h3>

</div>
</@layout.registrationLayout>
