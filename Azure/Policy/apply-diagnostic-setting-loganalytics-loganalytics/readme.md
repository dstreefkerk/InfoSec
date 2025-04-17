# Apply Audit Diagnostic Settings for Log Analytics Workspaces

This policy automatically deploys diagnostic settings for Log Analytics Workspaces to stream audit logs (not metrics by default) to a designated central Log Analytics workspace.

## Try on Portal

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fdstreefkerk%2Finfosec%2Fazure%2Fpolicy%2Fapply-diagnostic-setting-loganalytics-loganalytics%2Fazurepolicy.json)

## Purpose

This policy helps you:
- Maintain a consistent audit trail across all your Log Analytics workspaces
- Monitor for security and compliance purposes
- Consolidate audit logs in a central workspace for comprehensive analysis
- Automatically configure new workspaces as they're created

## Try with PowerShell

```powershell
$definition = New-AzPolicyDefinition -Name "apply-audit-diagnostic-setting-loganalytics" -DisplayName "Apply Audit Diagnostic Settings for Log Analytics Workspaces" -description "This policy automatically deploys diagnostic settings for Log Analytics Workspaces to stream audit logs (not metrics by default) to a designated Log Analytics workspace." -Policy 'https://path-to-your-repo/azurepolicy.rules.json' -Parameter 'https://path-to-your-repo/azurepolicy.parameters.json' -Mode Indexed
$definition

# Replace the placeholders with your actual values
$assignment = New-AzPolicyAssignment -Name "ensure-la-auditing" -Scope "/subscriptions/YOUR-SUBSCRIPTION-ID" -profileName "la-audit-logs" -logAnalytics "/subscriptions/YOUR-SUBSCRIPTION-ID/resourceGroups/YOUR-RG/providers/Microsoft.OperationalInsights/workspaces/YOUR-CENTRAL-WORKSPACE" -azureRegions @("australiaeast", "australiasoutheast") -metricsEnabled "False" -logsEnabled "True" -PolicyDefinition $definition
$assignment
```

## Try with CLI

```bash
az policy definition create --name 'apply-audit-diagnostic-setting-loganalytics' --display-name 'Apply Audit Diagnostic Settings for Log Analytics Workspaces' --description 'This policy automatically deploys diagnostic settings for Log Analytics Workspaces to stream audit logs (not metrics by default) to a designated Log Analytics workspace.' --rules 'https://path-to-your-repo/azurepolicy.rules.json' --params 'https://path-to-your-repo/azurepolicy.parameters.json' --mode Indexed

# Replace the placeholders with your actual values
az policy assignment create --name "ensure-la-auditing" --scope "/subscriptions/YOUR-SUBSCRIPTION-ID" --params "{ 'profileName': { 'value': 'la-audit-logs' }, 'logAnalytics': { 'value': '/subscriptions/YOUR-SUBSCRIPTION-ID/resourceGroups/YOUR-RG/providers/Microsoft.OperationalInsights/workspaces/YOUR-CENTRAL-WORKSPACE' }, 'azureRegions': { 'value': ['australiaeast', 'australiasoutheast'] }, 'metricsEnabled': { 'value': 'False' }, 'logsEnabled': { 'value': 'True' } }" --policy "apply-audit-diagnostic-setting-loganalytics"
```

## Policy Details

This policy:
- Targets all Log Analytics workspaces in specified Azure regions
- Checks if diagnostic settings are already configured
- Deploys diagnostic settings if they don't exist
- Configures audit logs to be sent to your central workspace
- Disables metrics collection by default (can be enabled via parameter)# Apply Audit Diagnostic Settings for Log Analytics Workspaces

This policy automatically deploys diagnostic settings for Log Analytics Workspaces to stream audit logs (not metrics by default) to a designated central Log Analytics workspace.

## Try on Portal

[![Deploy to Azure](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/https%3A%2F%2Fraw.githubusercontent.com%2F{{ github.repository_owner }}%2F{{ github.repository.name }}%2F{{ github.ref_name }}%2Fsamples%2FMonitoring%2Fapply-audit-diagnostic-setting-loganalytics%2Fazurepolicy.json)

## Purpose

This policy helps you:
- Maintain a consistent audit trail across all your Log Analytics workspaces
- Monitor for security and compliance purposes
- Consolidate audit logs in a central workspace for comprehensive analysis
- Automatically configure new workspaces as they're created

## Try with PowerShell

```powershell
$definition = New-AzPolicyDefinition -Name "apply-audit-diagnostic-setting-loganalytics" -DisplayName "Apply Audit Diagnostic Settings for Log Analytics Workspaces" -description "This policy automatically deploys diagnostic settings for Log Analytics Workspaces to stream audit logs (not metrics by default) to a designated Log Analytics workspace." -Policy 'https://path-to-your-repo/azurepolicy.rules.json' -Parameter 'https://path-to-your-repo/azurepolicy.parameters.json' -Mode Indexed
$definition

# Replace the placeholders with your actual values
$assignment = New-AzPolicyAssignment -Name "ensure-la-auditing" -Scope "/subscriptions/YOUR-SUBSCRIPTION-ID" -profileName "la-audit-logs" -logAnalytics "/subscriptions/YOUR-SUBSCRIPTION-ID/resourceGroups/YOUR-RG/providers/Microsoft.OperationalInsights/workspaces/YOUR-CENTRAL-WORKSPACE" -azureRegions @("australiaeast", "australiasoutheast") -metricsEnabled "False" -logsEnabled "True" -PolicyDefinition $definition
$assignment
```

## Try with CLI

```bash
az policy definition create --name 'apply-audit-diagnostic-setting-loganalytics' --display-name 'Apply Audit Diagnostic Settings for Log Analytics Workspaces' --description 'This policy automatically deploys diagnostic settings for Log Analytics Workspaces to stream audit logs (not metrics by default) to a designated Log Analytics workspace.' --rules 'https://path-to-your-repo/azurepolicy.rules.json' --params 'https://path-to-your-repo/azurepolicy.parameters.json' --mode Indexed

# Replace the placeholders with your actual values
az policy assignment create --name "ensure-la-auditing" --scope "/subscriptions/YOUR-SUBSCRIPTION-ID" --params "{ 'profileName': { 'value': 'la-audit-logs' }, 'logAnalytics': { 'value': '/subscriptions/YOUR-SUBSCRIPTION-ID/resourceGroups/YOUR-RG/providers/Microsoft.OperationalInsights/workspaces/YOUR-CENTRAL-WORKSPACE' }, 'azureRegions': { 'value': ['australiaeast', 'australiasoutheast'] }, 'metricsEnabled': { 'value': 'False' }, 'logsEnabled': { 'value': 'True' } }" --policy "apply-audit-diagnostic-setting-loganalytics"
```

## Policy Details

This policy:
- Targets all Log Analytics workspaces in specified Azure regions
- Checks if diagnostic settings are already configured
- Deploys diagnostic settings if they don't exist
- Configures audit logs to be sent to your central workspace
- Disables metrics collection by default (can be enabled via parameter)