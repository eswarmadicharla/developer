#!/bin/bash
# === Configuration Variables ===
RESOURCE_GROUP="modusEtpResourceGroup"
LOCATION="eastus2" 
VNET_NAME="modusEtpVnet"
APP_GATEWAY_SUBNET_NAME="AppGatewaySubnet"
APP_SERVICE_SUBNET_NAME="AppServiceSubnet"
PRIVATE_ENDPOINT_SUBNET_NAME="PrivateEndpointSubnet"
VNET_CIDR="10.0.0.0/16"
APP_GATEWAY_SUBNET_CIDR="10.0.1.0/24"
APP_SERVICE_SUBNET_CIDR="10.0.2.0/24"
PRIVATE_ENDPOINT_SUBNET_CIDR="10.0.3.0/24"
APP_GATEWAY_NAME="modusEtpGateway"
PUBLIC_IP_NAME="modusEtpGatewayPip"
APP_GATEWAY_SKU="WAF_v2" 
APP_GATEWAY_TIER="WAF_v2"
APP_SERVICE_PLAN_NAME="modusEtpServicePlan"
APP_SERVICE_PLAN_SKU="P1v3" 
APP_SERVICE_NAME="modusetpwebapp-$(openssl rand -hex 4)" 
RUNTIME="DOTNETCORE:6.0" # Or NODE:18-lts, PYTHON:3.10, etc.
SQL_SERVER_NAME="modussqlserver-$(openssl rand -hex 4)" 
SQL_DATABASE_NAME="modusEtpDatabase"
SQL_ADMIN_USER="eswarmadicharla"
SQL_ADMIN_PASSWORD="qPskcb#128" 
SQL_SKU="BC_Gen5_2" 
KEY_VAULT_NAME="moduskeyvault-$(openssl rand -hex 4)" 
# === Script ===
echo "Creating Resource Group: $RESOURCE_GROUP..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

echo "Creating Virtual Network: $VNET_NAME..."
az network vnet create \
  --name "$VNET_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --address-prefix "$VNET_CIDR"

echo "Creating Subnets..."
# App Gateway Subnet
az network vnet subnet create \
  --name "$APP_GATEWAY_SUBNET_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --address-prefix "$APP_GATEWAY_SUBNET_CIDR"

# App Service Subnet (Requires delegation)
az network vnet subnet create \
  --name "$APP_SERVICE_SUBNET_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --address-prefix "$APP_SERVICE_SUBNET_CIDR" \
  --delegations "Microsoft.Web/serverFarms"

# Private Endpoint Subnet (Disable private endpoint network policies)
az network vnet subnet create \
  --name "$PRIVATE_ENDPOINT_SUBNET_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --address-prefix "$PRIVATE_ENDPOINT_SUBNET_CIDR" \
  --disable-private-endpoint-network-policies true # Required for Private Endpoints

echo "Creating Public IP for Application Gateway..."
az network public-ip create \
  --name "$PUBLIC_IP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --allocation-method "Static" \
  --sku "Standard" \
  --zone 1 2 3 # Zone redundant

echo "Creating Application Gateway: $APP_GATEWAY_NAME (This may take ~20-30 minutes)..."
az network application-gateway create \
  --name "$APP_GATEWAY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku "$APP_GATEWAY_SKU" \
  --tier "$APP_GATEWAY_TIER" \
  --public-ip-address "$PUBLIC_IP_NAME" \
  --vnet-name "$VNET_NAME" \
  --subnet "$APP_GATEWAY_SUBNET_NAME" \
  --zones 1 2 3 # Zone redundant
  # Note: Backend pools, listeners, rules will be configured later or point to a dummy initially.

# WAF Policy (Optional but Recommended)
WAF_POLICY_NAME="myWafPolicy"
echo "Creating WAF Policy..."
az network application-gateway waf-policy create \
  --name $WAF_POLICY_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

echo "Associating WAF Policy with App Gateway..."
az network application-gateway update \
    --name $APP_GATEWAY_NAME \
    --resource-group $RESOURCE_GROUP \
    --set webApplicationFirewallConfiguration.enabled=true \
    --set webApplicationFirewallConfiguration.firewallMode=Prevention \
    --set webApplicationFirewallConfiguration.ruleSetType=OWASP \
    --set webApplicationFirewallConfiguration.ruleSetVersion=3.1 \
    --set gatewayIpConfigurations[0].firewallPolicy.id=$(az network application-gateway waf-policy show --name $WAF_POLICY_NAME --resource-group $RESOURCE_GROUP --query id --output tsv)


echo "Creating App Service Plan: $APP_SERVICE_PLAN_NAME..."
az appservice plan create \
  --name "$APP_SERVICE_PLAN_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku "$APP_SERVICE_PLAN_SKU" \
  --is-linux false # Set to true for Linux App Service Plan \
  --zone-redundant true # Enable zone redundancy

echo "Creating App Service: $APP_SERVICE_NAME..."
az webapp create \
  --name "$APP_SERVICE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --plan "$APP_SERVICE_PLAN_NAME" \
  --runtime "$RUNTIME"

echo "Enabling Managed Identity for App Service..."
az webapp identity assign \
  --name "$APP_SERVICE_NAME" \
  --resource-group "$RESOURCE_GROUP"
APP_SERVICE_PRINCIPAL_ID=$(az webapp identity show --name "$APP_SERVICE_NAME" --resource-group "$RESOURCE_GROUP" --query principalId --output tsv)
APP_SERVICE_ID=$(az webapp show --name "$APP_SERVICE_NAME" --resource-group "$RESOURCE_GROUP" --query id --output tsv)

echo "Configuring App Service VNet Integration..."
az webapp vnet-integration add \
  --name "$APP_SERVICE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet "$VNET_NAME" \
  --subnet "$APP_SERVICE_SUBNET_NAME"

# echo "Restricting App Service Access (Example: Allow only App Gateway Subnet - Adjust CIDR as needed)..."
# This part is complex via CLI and often easier in Portal/ARM/Bicep or via App Gateway config
# az webapp config access-restriction add --resource-group $RESOURCE_GROUP --name $APP_SERVICE_NAME \
#   --rule-name "AllowAppGateway" --action Allow --ip-address $APP_GATEWAY_SUBNET_CIDR --priority 100 \
#   --subnet $APP_GATEWAY_SUBNET_NAME --vnet $VNET_NAME
# az webapp config access-restriction set --resource-group $RESOURCE_GROUP --name $APP_SERVICE_NAME --use-same-restrictions-for-scm-site true
# az webapp config access-restriction remove --resource-group $RESOURCE_GROUP --name $APP_SERVICE_NAME --rule-name "Allow all" # Remove default allow rule


echo "Creating Azure SQL Server: $SQL_SERVER_NAME..."
az sql server create \
  --name "$SQL_SERVER_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --admin-user "$SQL_ADMIN_USER" \
  --admin-password "$SQL_ADMIN_PASSWORD"

echo "Creating Azure SQL Database: $SQL_DATABASE_NAME..."
az sql db create \
  --name "$SQL_DATABASE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --server "$SQL_SERVER_NAME" \
  --edition "BusinessCritical" \
  --family "Gen5" \
  --capacity 2 # Corresponds to BC_Gen5_2 SKU vCores
  # --zone-redundant true # Enable zone redundancy for BC/Premium

echo "Disabling Public Access to SQL Server..."
az sql server update \
  --name "$SQL_SERVER_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-access "Disabled"

echo "Creating Private Endpoint for SQL Server..."
SQL_SERVER_ID=$(az sql server show --name "$SQL_SERVER_NAME" --resource-group "$RESOURCE_GROUP" --query id --output tsv)
az network private-endpoint create \
  --name "pe-$SQL_SERVER_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --subnet "$PRIVATE_ENDPOINT_SUBNET_NAME" \
  --private-connection-resource-id "$SQL_SERVER_ID" \
  --group-ids "sqlServer" \
  --connection-name "conn-$SQL_SERVER_NAME" \
  --location "$LOCATION"

echo "Creating Private DNS Zone for SQL..."
az network private-dns zone create \
  --name "privatelink.database.windows.net" \
  --resource-group "$RESOURCE_GROUP"

echo "Linking Private DNS Zone to VNet..."
az network private-dns link vnet create \
  --name "sql-dns-link" \
  --resource-group "$RESOURCE_GROUP" \
  --zone-name "privatelink.database.windows.net" \
  --virtual-network "$VNET_NAME" \
  --registration-enabled false

echo "Creating DNS Zone Group for SQL Private Endpoint..."
SQL_PE_ID=$(az network private-endpoint show --name "pe-$SQL_SERVER_NAME" --resource-group "$RESOURCE_GROUP" --query id --output tsv)
az network private-endpoint dns-zone-group create \
    --resource-group $RESOURCE_GROUP \
    --endpoint-name "pe-$SQL_SERVER_NAME" \
    --name "sql-zone-group" \
    --private-dns-zone "privatelink.database.windows.net" \
    --zone-name sqlServer # This should match the --group-ids used before

echo "Creating Key Vault: $KEY_VAULT_NAME..."
az keyvault create \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku "Standard" \
  --enable-rbac-authorization false # Use access policies for simplicity here, RBAC is preferred
  # --enable-private-link true # Add flags for private endpoint if needed

echo "Granting App Service Managed Identity GET secrets permission on Key Vault..."
az keyvault set-policy \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --object-id "$APP_SERVICE_PRINCIPAL_ID" \
  --secret-permissions get list

echo "Storing SQL Connection String in Key Vault (Example)..."
# Construct the connection string - Use Managed Identity (Authentication=Active Directory Managed Identity) if possible!
# Or store the password securely if using SQL Auth
# SQL_CONNECTION_STRING="Server=tcp:$SQL_SERVER_NAME.database.windows.net,1433;Database=$SQL_DATABASE_NAME;User ID=$SQL_ADMIN_USER;Password=$SQL_ADMIN_PASSWORD;Encrypt=true;TrustServerCertificate=false;Connection Timeout=30;"
# az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "SQLConnectionString" --value "$SQL_CONNECTION_STRING"
# Recommended: Use Managed Identity
SQL_CONNECTION_STRING_MSI="Server=tcp:$SQL_SERVER_NAME.database.windows.net,1433;Database=$SQL_DATABASE_NAME;Authentication=Active Directory Managed Identity;Encrypt=true;TrustServerCertificate=false;Connection Timeout=30;"
az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "SQLConnectionStringMSI" --value "$SQL_CONNECTION_STRING_MSI"

echo "Configuring App Service Application Setting to reference Key Vault secret..."
KV_URI=$(az keyvault show --name $KEY_VAULT_NAME --resource-group $RESOURCE_GROUP --query properties.vaultUri --output tsv)
SECRET_REFERENCE="@Microsoft.KeyVault(VaultName=$KEY_VAULT_NAME;SecretName=SQLConnectionStringMSI)"
az webapp config appsettings set \
  --name "$APP_SERVICE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --settings "SQLConnectionString=$SECRET_REFERENCE"

echo "Configuring App Gateway Backend Pool, HTTP Settings, Listener, and Rule..."
# Get App Gateway ID
APP_GATEWAY_ID=$(az network application-gateway show --name $APP_GATEWAY_NAME --resource-group $RESOURCE_GROUP --query id --output tsv)

# Backend Pool
az network application-gateway address-pool create \
    --gateway-name $APP_GATEWAY_NAME \
    --resource-group $RESOURCE_GROUP \
    --name myBackendPool \
    --servers $APP_SERVICE_NAME.azurewebsites.net

# HTTP Setting
az network application-gateway http-settings create \
    --gateway-name $APP_GATEWAY_NAME \
    --resource-group $RESOURCE_GROUP \
    --name myHTTPSetting \
    --port 80 \
    --protocol Http \
    --cookie-based-affinity Disabled \
    --host-name-from-backend-pool true # Important for App Service

# Frontend Port
az network application-gateway frontend-port create \
    --gateway-name $APP_GATEWAY_NAME \
    --resource-group $RESOURCE_GROUP \
    --name port_443 \
    --port 443

# Listener (Requires SSL Cert - Placeholder, assumes cert in Key Vault or uploaded)
# You would typically add --ssl-cert <cert-name> referencing a cert uploaded to App Gateway
# For testing, you can create an HTTP listener on port 80 first
az network application-gateway http-listener create \
    --gateway-name $APP_GATEWAY_NAME \
    --resource-group $RESOURCE_GROUP \
    --name myListener \
    --frontend-ip applicationGatewayFrontendIP # Default frontend IP
    --frontend-port port_443 \
    --protocol Https \
    --ssl-certificate "<Your-Cert-Name-In-AppGw>" # Add your cert reference here!

# Request Routing Rule
az network application-gateway rule create \
    --gateway-name $APP_GATEWAY_NAME \
    --resource-group $RESOURCE_GROUP \
    --name myRule \
    --http-listener myListener \
    --rule-type Basic \
    --address-pool myBackendPool \
    --http-settings myHTTPSetting

echo "--- Infrastructure Deployment Complete ---"
echo "App Service Name: $APP_SERVICE_NAME"
echo "App Service Hostname: $APP_SERVICE_NAME.azurewebsites.net"
APP_GW_IP=$(az network public-ip show --name $PUBLIC_IP_NAME --resource-group $RESOURCE_GROUP --query ipAddress --output tsv)
echo "Application Gateway Public IP: $APP_GW_IP"
echo "SQL Server: $SQL_SERVER_NAME.database.windows.net"
echo "Key Vault Name: $KEY_VAULT_NAME"
echo "NOTE: Configure DNS for your custom domain to point to the Application Gateway IP: $APP_GW_IP"
echo "NOTE: Upload and configure SSL Certificate '$<Your-Cert-Name-In-AppGw>' in Application Gateway $APP_GATEWAY_NAME"
echo "NOTE: Ensure the App Service Managed Identity ($APP_SERVICE_PRINCIPAL_ID) is added as a user/role in the SQL Database for MSI authentication."
