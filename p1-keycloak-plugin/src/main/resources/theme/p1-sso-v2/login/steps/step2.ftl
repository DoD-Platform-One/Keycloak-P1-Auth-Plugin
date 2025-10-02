<div>
  <ul class="step-counter">
    <li class="step step-0">
      <span class="sr-only">Step&nbsp;</span>
      <span>1</span>
      <span class="sr-only">&nbsp;of 5</span>
    </li>
    <li class="step step-1 current active">
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

<div class="review-step">
    <h2>Step 2: Review your information</h2>
    <p>Below is the information you entered. If anything is incorrect, please go back and fix it.</p>
    <p>Reminder: your username cannot be changed after you submit.</p>

    <div class="table-table">
        <div class="table-row">
            <div class="table-label">Name</div>
            <div class="table-value" id="review-name"></div>
        </div>
        
        <div class="table-row">
            <div class="table-label">Email</div>
            <div class="table-value" id="review-email"></div>
        </div>
        
        <div class="table-row">
            <div class="table-label">Affiliation</div>
            <div class="table-value" id="review-affiliation"></div>
        </div>
        
        <div class="table-row">
            <div class="table-label">Pay grade</div>
            <div class="table-value" id="review-rank"></div>
        </div>
        
        <div class="table-row">
            <div class="table-label">Organization</div>
            <div class="table-value" id="review-organization"></div>
        </div>
        
        <div class="table-row">
            <div class="table-label">Username</div>
            <div class="table-value" id="review-username"></div>
        </div>
        
        <#if cacIdentity??>
        <div class="table-row cac-identity">
            <div class="table-label">CAC Identity</div>
            <div class="table-value">${cacIdentity}</div>
        </div>
        
        <div class="table-row">
            <div class="table-label">DoD ID Number</div>
            <div class="table-value" id="review-dodid">
                <#-- Extract DoD ID Number from CAC Identity -->
                <#assign dodIdNumber = "">
                <#assign parts = cacIdentity?split(".")>
                <#if parts?size gt 0>
                    <#assign lastPart = parts[parts?size-1]>
                    <#if lastPart?matches("\\d+")>
                        <#assign dodIdNumber = lastPart>
                    </#if>
                </#if>
                ${dodIdNumber}
            </div>
        </div>
        
        </#if>
        
        <div class="table-row" id="review-password-row" style="display:none;">
            <div class="table-label">Password</div>
            <div class="table-value">Set</div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', () => {
        // Function to populate review data when step 3 is shown
        function populateReviewData() {
            // Get form elements
            const firstName = document.getElementById('firstName');
            const lastName = document.getElementById('lastName');
            const email = document.getElementById('email');
            const username = document.getElementById('username');
            const affiliation = document.getElementById('user.attributes.affiliation');
            const rank = document.getElementById('user.attributes.rank');
            const organization = document.getElementById('user.attributes.organization');
            const password = document.getElementById('password');
            
            // Populate review fields
            if (firstName && lastName) {
                document.getElementById('review-name').textContent = firstName.value + ' ' + lastName.value;
            }
            
            if (email) {
                document.getElementById('review-email').textContent = email.value;
            }
            
            if (affiliation) {
                document.getElementById('review-affiliation').textContent = affiliation.value;
            }
            
            if (rank) {
                document.getElementById('review-rank').textContent = rank.value;
            }
            
            if (organization) {
                document.getElementById('review-organization').textContent = organization.value;
            }
            
            if (username) {
                document.getElementById('review-username').textContent = username.value;
            }
            
            if (password && password.value) {
                document.getElementById('review-password-row').style.display = 'flex';
            }
            
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
        }
        
        // Check if we're on step 2 (review page) and populate data
        const nextBtn = document.getElementById('next-step');
        const prevBtn = document.getElementById('prev-step');
        const submitBtn = document.getElementById('submit-form');
        
        if (nextBtn && prevBtn && submitBtn) {
            // Listen for step changes - populate when we reach step 2
            const originalShowStep = window.showStep;
            if (originalShowStep) {
                window.showStep = function(step) {
                    originalShowStep(step);
                    if (step === 2) {
                        setTimeout(() => {
                            populateReviewData();
                            submitBtn.value = "Submit & Continue";
                        }, 50);
                    }
                };
            }
            
            // Also check on page load if we're already on step 2
            setTimeout(() => {
                const currentStep = document.getElementById('step').value;
                if (currentStep === '2') {
                    populateReviewData();
                    submitBtn.value = "Submit & Continue";
                }
            }, 100);
        }
    });
</script>
