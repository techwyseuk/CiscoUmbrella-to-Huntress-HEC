# Cisco Umbrella to Huntress HEC Log Shipping

This project provides two versions of a PowerShell script to ship logs from Cisco Umbrella Portal to Huntress using the HEC (HTTP Event Collector) format.

**⚠️ PowerShell 7+ Required**: This project requires PowerShell 7 or later. It will not work with Windows PowerShell 5.1.

## Features

- **Batched Processing**: 200 events per HTTP request
- **Comprehensive Field Mapping**: All Cisco Umbrella fields mapped to Huntress ECS format
- **Flattened Data Structure**: Complex nested objects expanded for better SIEM visibility
- **Multiple Log Types**: DNS, Proxy, Firewall, Intrusion, and IP logs
- **Incremental Processing**: 10-minute lookback window for efficient processing
- **State Management**: Tracks last run time to prevent duplicates

## Scripts

### Standalone Version (`CiscoUmbrellaToHEC-Standalone.ps1`)
- **Purpose**: Run locally to test it out (Requires: PowerShell 7+)
- **Features**: 
  - Batched HTTP requests (200 events per request)
  - Progress indicators
- **Usage**: `pwsh -ExecutionPolicy Bypass -File "CiscoUmbrellaToHEC-Standalone.ps1"`
- **Required Parameters**
  - `ApiKey`: Cisco Umbrella API Key
  - `ApiSecret`: Cisco Umbrella API Secret  
  - `HuntressHecToken`: Huntress HEC Token

### Azure Functions Version (`CiscoUmbrellaToHEC/`)
- **Purpose**: Deploy as an Azure Function for automated execution
- **Features**:
  - Same batched processing as standalone
  - Timer-triggered execution
  - Environment variable configuration
  - Azure Function return format
- **Deployment**: Use the deploy to Azure Button below or follow the steps for manual deployment
- **Environment Variables**
  - `UMBRELLA_API_KEY`: Cisco Umbrella API Key
  - `UMBRELLA_API_SECRET`: Cisco Umbrella API Secret
  - `HUNTRESS_HEC_TOKEN`: Huntress HEC Token


## Deployment

### 🚀 One-Click Azure Deployment

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FLukeSteward%2FCiscoUmbrella-to-Huntress-HEC%2Frefs%2Fheads%2Fmain%2Fdeployments%2Fazuredeploy.json)


The deployment will prompt you for:
- **Cisco Umbrella API Key**: Cisco Umbrella API Key (Inside of Customer)
- **Cisco Umbrella API Secret**: Cisco Umbrella API Secret
- **Huntress HEC Token**: Huntress HEC Token

### 📦 Deploy Function Code

After the infrastructure is deployed, you need to deploy the function code.

#### GitHub Deployment (Recommended)

1. **Fork this repository** to your GitHub account
2. **Go to Azure Portal** → Your Function App → **Deployment Center**
3. **Select GitHub** as source
4. **Authorize** and select your forked repository
5. **Choose branch**: `main`
6. **Set application path**: `CiscoUmbrellaToHEC`
7. **Save** - Azure will automatically deploy your function code


## Project Structure

```
Cisco_to_HEC/
├── CiscoUmbrellaToHEC-Standalone.ps1    # Standalone PowerShell script
├── host.json                             # Host configuration
├── CiscoUmbrellaToHEC/                   # Azure Functions deployment
│   ├── run.ps1                          # Azure Function entry point
│   ├── function.json                    # Function configuration
│   └── .funcignore                      # Exclusions for deployment
└── last_run_state.json                  # State tracking file
```
