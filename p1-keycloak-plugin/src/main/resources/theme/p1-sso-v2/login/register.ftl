<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('firstName','lastName','email','username','password','password-confirm'); section>
<#if section == "form">
  <form id="multi-step-form" method="post" action="${url.registrationAction}">
    <input type="hidden" name="step" id="step" value="0"/>

    <div class="step-content" data-step="0">
      <#include "steps/step0.ftl">
    </div>

    <div class="step-content hidden" data-step="1">
      <#include "steps/step1.ftl">
    </div>

    <div class="step-content hidden" data-step="2">
      <#include "steps/step2.ftl">
    </div>

    <div class="step-content hidden" data-step="3">
      <#include "steps/step3.ftl">
    </div>

    <div class="form-navigation flex justify-space-between">
      <button type="button" id="prev-step" class="btn btn-neutral outline hidden"><span class="icon prepend arrow-left"></span>Back</button>
      <span></span>
      <button type="button" id="next-step" class="btn btn-primary">Continue<span class="icon append arrow-right"></span></button>
      <button type="submit" id="submit-form" class="btn btn-primary hidden" value="Submit & Continue"><span class="icon prepend lock"></span>Submit & Continue<span class="icon append arrow-right"></span></button>
    </div>
  </form>
</#if>
</@layout.registrationLayout>

<script>
  document.getElementById('user.attributes.affiliation').value = "${(register.formData['user.attributes.affiliation']!'')}";
  document.getElementById('user.attributes.rank').value = "${(register.formData['user.attributes.rank']!'')}";
  
  // Override the error detection logic from grogu.js
  document.addEventListener('DOMContentLoaded', () => {
    // Check if we have a server error and repopulated form data
    const hasServerError = <#if message?has_content>true<#else>false</#if>;
    const hasRepopulatedData = <#if register.formData.username?? || register.formData.email?? || register.formData.firstName??>true<#else>false</#if>;
    
    if (hasServerError && hasRepopulatedData) {
      console.log("Server error detected with repopulated data, showing Step 1.");
      // Force the form to show step 1
      const stepInput = document.getElementById('step');
      const steps = document.querySelectorAll('.step-content');
      const prevBtn = document.getElementById('prev-step');
      const nextBtn = document.getElementById('next-step');
      const submitBtn = document.getElementById('submit-form');
      
      if (stepInput) {
        stepInput.value = 1;
      }
      
      // Show step 1 content
      steps.forEach(s => {
        s.classList.toggle('hidden', parseInt(s.dataset.step) !== 1);
      });
      
      // Update button visibility
      if (prevBtn) prevBtn.classList.remove('hidden');
      if (nextBtn) nextBtn.classList.remove('hidden');
      if (submitBtn) submitBtn.classList.add('hidden');
      
      // Update the currentStep variable if it exists in the global scope
      if (typeof window.currentStep !== 'undefined') {
        window.currentStep = 1;
      }
    }
  });
</script>
