<!-- Add this to step1.ftl after the location field (around line 176) -->

<!-- Mattermost Persona Field (Optional) -->
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

<!-- 
Notes:
- JavaScript validation for this field is handled in grogu.js
- Configuration details are in MATTERMOST_PROVISIONING_README.md
- YAML configuration examples are in customreg-mattermost-example.yaml
-->