# Single Keycloak Instance Supporting Multiple Impact Levels

Since you have **ONE Keycloak instance** serving all impact levels, here's the updated configuration approach:

## Environment Variables

```bash
# NO IMPACT_LEVEL variable needed anymore!

# Mattermost Provisioning Tokens (one per environment)
MATTERMOST_TEST_PROVISION_TOKEN=pvt_xxxxx_test
MATTERMOST_IL2_PROVISION_TOKEN=pvt_xxxxx_il2
MATTERMOST_IL4_PROVISION_TOKEN=pvt_xxxxx_il4
MATTERMOST_IL5_PROVISION_TOKEN=pvt_xxxxx_il5

# Path to YAML config
CUSTOM_REGISTRATION_CONFIG=/opt/keycloak/conf/customreg.yaml
```

## YAML Configuration (customreg.yaml)

```yaml
# Your existing config sections
x509:
  userIdentityAttribute: "usercertificate"
  userActive509Attribute: "activecac"
  autoJoinGroup:
    - "/Impact Level 2 Authorized"
  # ... etc

# Mattermost Provisioning Configuration
mattermostProvisioning:
  enabled: true  # Master enable/disable switch
  requestTimeoutSeconds: 30
  
  environments:
    TEST:
      enabled: true  # Enable/disable TEST provisioning
      provisionUrl: "https://chat.test.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_TEST_PROVISION_TOKEN}"
    
    IL2:
      enabled: true  # Enable/disable IL2 provisioning
      provisionUrl: "https://chat.il2.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL2_PROVISION_TOKEN}"
    
    IL4:
      enabled: true  # Enable/disable IL4 provisioning
      provisionUrl: "https://chat.il4.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL4_PROVISION_TOKEN}"
    
    IL5:
      enabled: false  # Disable IL5 for now (example)
      provisionUrl: "https://chat.il5.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL5_PROVISION_TOKEN}"
```

## How It Works Now

When a user registers with persona `123-ORG-role`:

1. **Event listener triggers** on VERIFY_EMAIL event
2. **For each enabled environment** (TEST, IL2, IL4, IL5):
   - Calls that environment's Mattermost provisioning endpoint with user's persona
   - Mattermost handles its own Jira lookups internally
   - Tracks success/failure per environment
3. **Updates user attributes**:
   - `mattermost_provisioned`: "true" (if at least one succeeded)
   - `mattermost_provisioned_environments`: "TEST,IL2,IL4" (which ones succeeded)
   - `mattermost_provisioned_failed`: "IL5" (which ones failed, if any)

## Controlling Which Environments Are Active

### Option 1: Enable/Disable in YAML
```yaml
environments:
  TEST:
    enabled: true   # This user will be provisioned in TEST
  IL2:
    enabled: true   # This user will be provisioned in IL2
  IL4:
    enabled: true   # This user will be provisioned in IL4
  IL5:
    enabled: false  # This user will NOT be provisioned in IL5
```

### Option 2: Environment Variable Override
```yaml
environments:
  TEST:
    enabled: "${TEST_PROVISIONING_ENABLED:true}"  # Defaults to true
  IL2:
    enabled: "${IL2_PROVISIONING_ENABLED:true}"   # Defaults to true
  IL4:
    enabled: "${IL4_PROVISIONING_ENABLED:true}"
  IL5:
    enabled: "${IL5_PROVISIONING_ENABLED:false}"  # Defaults to false
```

Then set in Kubernetes:
```bash
TEST_PROVISIONING_ENABLED=true
IL2_PROVISIONING_ENABLED=true
IL4_PROVISIONING_ENABLED=true
IL5_PROVISIONING_ENABLED=false
```

## Mattermost Provisioning Behavior

The system provisions users directly in Mattermost:
1. Extracts user's persona attribute from Keycloak
2. For each enabled environment (TEST, IL2, IL4, IL5):
   - Sends provisioning request to Mattermost
   - Mattermost handles its own Jira lookups internally
3. Tracks which environments succeeded/failed in user attributes

## User Attributes After Provisioning

```json
{
  "mattermost_provisioned": "true",
  "mattermost_provisioned_date": "1696123456789",
  "mattermost_provisioned_environments": "IL2,IL4",
  "mattermost_provisioned_failed": "IL5",
  "persona": "123-ORG-role"
}
```

## Testing Scenarios

### Test 1: All Environments Enabled
```yaml
IL2: enabled: true
IL4: enabled: true
IL5: enabled: true
```
Result: User provisioned in all 4 Mattermosts

### Test 2: Only IL4 Enabled
```yaml
IL2: enabled: false
IL4: enabled: true
IL5: enabled: false
```
Result: User only provisioned in IL4 Mattermost

### Test 3: Master Switch Off
```yaml
mattermostProvisioning:
  enabled: false  # Nothing happens
```
Result: No provisioning occurs

## Monitoring

Check logs for multi-environment provisioning:
```
INFO  Provisioning user john.doe in environment: IL2
INFO  Successfully provisioned user john.doe in IL2
INFO  Provisioning user john.doe in environment: IL4
INFO  Successfully provisioned user john.doe in IL4
INFO  Skipping disabled environment: IL5
INFO  User john.doe provisioned in environments: [IL2, IL4]
```

## Benefits of This Approach

1. **Single Keycloak instance** manages all impact levels
2. **Flexible configuration** - enable/disable per environment
3. **Resilient** - failures in one IL don't affect others
4. **Efficient** - Jira responses cached across all environments
5. **Trackable** - User attributes show which ILs they're provisioned in