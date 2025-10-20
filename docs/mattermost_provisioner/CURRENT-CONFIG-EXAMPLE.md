# Current Configuration Example

This document shows the current Mattermost provisioning configuration that sends user data directly to Mattermost. Mattermost handles all Jira lookups internally.

## Environment Variables

```bash
# Mattermost Provisioning Tokens (one per environment)
MATTERMOST_TEST_PROVISION_TOKEN=pvt_xxxxxxxxxxxxx_test
MATTERMOST_IL2_PROVISION_TOKEN=pvt_xxxxxxxxxxxxx_il2
MATTERMOST_IL4_PROVISION_TOKEN=pvt_xxxxxxxxxxxxx_il4
MATTERMOST_IL5_PROVISION_TOKEN=pvt_xxxxxxxxxxxxx_il5

# Path to custom registration config
CUSTOM_REGISTRATION_CONFIG=/opt/keycloak/conf/customreg.yaml
```

## YAML Configuration (customreg.yaml)

```yaml
# Existing configuration sections
x509:
  userIdentityAttribute: "usercertificate"
  userActive509Attribute: "activecac"
  autoJoinGroup:
    - "/Impact Level 2 Authorized"
  requiredCertificatePolicies:
    - "2.16.840.1.101.2.1.11.36"
    - "2.16.840.1.101.3.2.1.12.2"
    - "2.16.840.1.101.3.2.1.12.3"

groupProtectionIgnoreClients:
  - "broker"
  - "realm-management"

noEmailMatchAutoJoinGroup:
  - "/NoEmailMatch"

emailMatchAutoJoinGroup:
  - domains:
      - ".mil"
      - "@mil"
    groups:
      - "/Impact Level 2 Authorized"

# Mattermost Provisioning Configuration
mattermostProvisioning:
  enabled: true  # Master enable/disable switch
  requestTimeoutSeconds: 30  # Timeout for HTTP requests to Mattermost
  
  environments:
    TEST:
      enabled: true  # Enable TEST environment
      provisionUrl: "https://chat.test.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_TEST_PROVISION_TOKEN}"
    
    IL2:
      enabled: true  # Enable IL2 provisioning
      provisionUrl: "https://chat.il2.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL2_PROVISION_TOKEN}"
    
    IL4:
      enabled: true  # Enable IL4 provisioning
      provisionUrl: "https://chat.il4.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL4_PROVISION_TOKEN}"
    
    IL5:
      enabled: false  # Disabled for this example
      provisionUrl: "https://chat.il5.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL5_PROVISION_TOKEN}"
```

## Kubernetes Secrets Configuration

```yaml
---
# Mattermost provisioning tokens
apiVersion: v1
kind: Secret
metadata:
  name: mattermost-provisioning-secrets
  namespace: keycloak
type: Opaque
stringData:
  test-token: "pvt_xxxxxxxxxxxxx_test"  # Replace with actual token
  il2-token: "pvt_xxxxxxxxxxxxx_il2"   # Replace with actual token
  il4-token: "pvt_xxxxxxxxxxxxx_il4"   # Replace with actual token
  il5-token: "pvt_xxxxxxxxxxxxx_il5"   # Replace with actual token

---
# ConfigMap with customreg.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: keycloak-customreg-config
  namespace: keycloak
data:
  customreg.yaml: |
    # Paste the full customreg.yaml content here
    # with ${ENV_VAR} references for secrets
```

## Helm Values

```yaml
keycloak:
  env:
    # Mattermost provisioning tokens
    - name: MATTERMOST_TEST_PROVISION_TOKEN
      valueFrom:
        secretKeyRef:
          name: mattermost-provisioning-secrets
          key: test-token
    
    - name: MATTERMOST_IL2_PROVISION_TOKEN
      valueFrom:
        secretKeyRef:
          name: mattermost-provisioning-secrets
          key: il2-token
    
    - name: MATTERMOST_IL4_PROVISION_TOKEN
      valueFrom:
        secretKeyRef:
          name: mattermost-provisioning-secrets
          key: il4-token
    
    - name: MATTERMOST_IL5_PROVISION_TOKEN
      valueFrom:
        secretKeyRef:
          name: mattermost-provisioning-secrets
          key: il5-token
    
    # Config file path
    - name: CUSTOM_REGISTRATION_CONFIG
      value: "/opt/keycloak/conf/customreg.yaml"

  volumeMounts:
    - name: customreg-config
      mountPath: /opt/keycloak/conf/customreg.yaml
      subPath: customreg.yaml
      readOnly: true

  volumes:
    - name: customreg-config
      configMap:
        name: keycloak-customreg-config
```

## Testing the Configuration

### 1. Verify Mattermost Endpoint

```bash
# Test Mattermost provisioning endpoint directly
curl -X POST "https://chat.il4.dso.mil/plugins/auto-provision/provision" \
  -H "Content-Type: application/json" \
  -H "X-Provision-Token: ${MATTERMOST_IL4_PROVISION_TOKEN}" \
  -H "Idempotency-Key: $(uuidgen)" \
  --data '{
    "username": "test.user",
    "mattermostId": "kc-user-id",
    "firstName": "Test",
    "lastName": "User",
    "email": "test.user@example.mil",
    "persona": "123-TEST-developer"
  }'
```

### 2. Enable Event Listener in Keycloak

1. Login to Keycloak Admin Console
2. Select your realm
3. Go to Events → Config
4. Add `mattermost-provisioning` to Event Listeners
5. Save

### 3. Test User Registration

Create a test user with a persona attribute:

```bash
# Using Keycloak Admin API
curl -X POST "https://keycloak.example.mil/auth/admin/realms/myrealm/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "username": "test.user",
    "email": "test.user@example.mil",
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "attributes": {
      "persona": ["123-TEST-developer"]
    }
  }'
```

## What Happens When a User Registers

Example: User registers with persona `123-TEST-developer`

1. **VERIFY_EMAIL Event** triggers the Mattermost provisioning listener
2. **For each enabled environment** (TEST, IL2, IL4):
   - Sends user data and persona to that environment's Mattermost
   - Mattermost plugin handles Jira lookups internally
   - Mattermost provisions user into appropriate teams/channels
3. **User attributes updated**:
   - `mattermost_provisioned`: "true"
   - `mattermost_provisioned_environments`: "TEST,IL2,IL4"
   - `mattermost_provisioned_date`: "1696123456789"

## Key Differences from Previous Implementation

- **No Jira configuration needed in Keycloak** - Mattermost handles this internally
- **Simpler configuration** - Only need Mattermost tokens and URLs
- **Direct provisioning** - Sends user data directly to Mattermost
- **Per-environment control** - Each environment can be enabled/disabled independently
- **Idempotency** - Uses idempotency keys to prevent duplicate provisioning

## Troubleshooting

### Common Issues

1. **User not provisioned**
   - Check if `persona` attribute is set
   - Verify event listener is enabled in realm
   - Check if `mattermostProvisioning.enabled` is true

2. **422 errors from Mattermost**
   - Persona lacks mapping in Mattermost's Jira
   - Contact Mattermost admin to verify persona mappings

3. **401 errors from Mattermost**
   - Provisioning token is invalid or expired
   - Check environment variable configuration

4. **Connection timeouts**
   - Increase `requestTimeoutSeconds` if needed
   - Check network connectivity to Mattermost

### Log Monitoring

Look for these log patterns in Keycloak:

```
INFO  [MattermostProvisioningEventListenerProvider] Provisioning user in Mattermost: test.user with persona: 123-TEST-developer
INFO  [MattermostProvisioningEventListenerProvider] Successfully provisioned user in Mattermost: test.user
```