# Azure Function: Cisco Umbrella MSP Portal to Huntress HEC Log Shipping
# Timer trigger function that runs every 5 minutes to ship logs from Cisco Umbrella to Huntress

# Input bindings: TimerTrigger (e.g. every 5 mins)
param($Timer)

# Get configuration from Azure Function App Settings
$umbrellaApiKey = $env:UMBRELLA_API_KEY
$umbrellaApiSecret = $env:UMBRELLA_API_SECRET
$huntressHecToken = $env:HUNTRESS_HEC_TOKEN

# Standard Huntress HEC URL (same for all customers)
$huntressHecUrl = "https://hec.huntress.io/services/collector/raw"

# Cisco Umbrella API endpoints (corrected based on Postman testing)
$umbrellaAuthUrl = "https://api.umbrella.com/auth/v2/token"
$umbrellaReportsBaseUrl = "https://api.umbrella.com/reports/v2"

# Function to get OAuth2 access token from Cisco Umbrella
function Get-UmbrellaAccessToken {
    param(
        [string]$ApiKey,
        [string]$ApiSecret
    )
    
    try {
        # Use Basic Auth with API key as username and secret as password
        $credential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ApiKey}:${ApiSecret}"))
        
        $authHeaders = @{
            "Authorization" = "Basic $credential"
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        
        $authBody = @{
            grant_type = "client_credentials"
        }
        
        $response = Invoke-RestMethod -Uri $umbrellaAuthUrl -Method Post -Headers $authHeaders -Body $authBody
        
        if ($response.access_token) {
            return $response.access_token
        } else {
            throw "Failed to obtain access token from Cisco Umbrella"
        }
    }
    catch {
        Write-Error "Error obtaining access token: $($_.Exception.Message)"
        return $null
    }
}

# Function to fetch logs from Cisco Umbrella
function Get-UmbrellaLogs {
    param(
        [string]$AccessToken,
        [string]$BaseUrl
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    # Define different log types to fetch (only working endpoints)
    $logTypes = @(
        "activity/dns",
        "activity/proxy",
        "activity/firewall"
    )
    
    $allLogs = [System.Collections.Generic.List[object]]::new()
    
    foreach ($logType in $logTypes) {
        try {
            $logUrl = "$BaseUrl/$logType" + "?from=-10minutes&to=now&limit=5000"
            Write-Host "Fetching $logType logs from: $logUrl"
            
            $response = Invoke-RestMethod -Uri $logUrl -Headers $headers -Method Get -TimeoutSec 60
            
            if ($response -and $response.data) {
                Write-Host "Retrieved $($response.data.Count) $logType events"
                
                # Add log type to each event for identification
                foreach ($logEventItem in $response.data) {
                    $logEventItem | Add-Member -NotePropertyName "log_type" -NotePropertyValue $logType -Force
                }
                $allLogs.AddRange($response.data)
            } else {
                Write-Host "No $logType data available"
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            Write-Warning "Failed to fetch $logType logs: $statusCode - $($_.Exception.Message)"
        }
    }
    
    return $allLogs
}

# Main execution
try {
    Write-Host "Starting Cisco Umbrella to Huntress HEC log shipping..."
    
    # Validate configuration
    if (-not $umbrellaApiKey -or -not $umbrellaApiSecret -or -not $huntressHecToken) {
        throw "Missing required configuration. Please set UMBRELLA_API_KEY, UMBRELLA_API_SECRET, and HUNTRESS_HEC_TOKEN in Function App Settings."
    }
    
    # Get OAuth2 access token
    Write-Host "Obtaining access token from Cisco Umbrella..."
    $accessToken = Get-UmbrellaAccessToken -ApiKey $umbrellaApiKey -ApiSecret $umbrellaApiSecret
    
    if (-not $accessToken) {
        throw "Failed to obtain access token. Check your API credentials."
    }
    
    Write-Host "Access token obtained successfully."
    
    # Fetch logs from Cisco Umbrella
    Write-Host "Fetching logs from Cisco Umbrella..."
    $logs = Get-UmbrellaLogs -AccessToken $accessToken -BaseUrl $umbrellaReportsBaseUrl
    
    if ($logs -and $logs.Count -gt 0) {
        Write-Host "Retrieved $($logs.Count) total log events from Cisco Umbrella."
        
        # Process each log event
        $successCount = 0
        $errorCount = 0
        
        Write-Host "Sending logs to Huntress in batches..."
        
        # Configuration for batched processing
        $batchSize = 200  # Send 200 events per HTTP request
        $totalBatches = [math]::Ceiling($logs.Count / $batchSize)
        
        Write-Host "Processing $($logs.Count) events in $totalBatches batches of $batchSize..."
        
        $startTime = Get-Date
        # Process events in batches for better performance
        for ($batchIndex = 0; $batchIndex -lt $totalBatches; $batchIndex++) {
            $startIndex = $batchIndex * $batchSize
            $endIndex = [math]::Min($startIndex + $batchSize - 1, $logs.Count - 1)
            $batchEvents = $logs[$startIndex..$endIndex]
            
            Write-Host "Processing batch $($batchIndex + 1)/$totalBatches (events $($startIndex + 1)-$($endIndex + 1))..."
            
            # Create batch payload
            $batchPayload = @()
            foreach ($logEvent in $batchEvents) {
                $hecEvent = @{
                            time = if ($logEvent.timestamp) { 
                                [math]::Round($logEvent.timestamp / 1000) 
                            } else { 
                                [math]::Round((Get-Date).ToUniversalTime().Subtract([datetime]"1970-01-01").TotalSeconds) 
                            }
                            host = $logEvent.internalip
                            source = "cisco_umbrella"
                            sourcetype = "cisco:umbrella:activity"
                            index = "main"
                            
                            # Core fields
                            provider = "cisco_umbrella"
                            product = "security"
                            category = "network"
                            type = $logEvent.type
                            dataset = $logEvent.log_type
                            log_type = $logEvent.log_type
                            
                            # Network fields
                            source_ip = $logEvent.internalip
                            destination_ip = $logEvent.destinationip
                            external_ip = $logEvent.externalip
                            domain = $logEvent.domain
                            url = $logEvent.url
                            verdict = $logEvent.verdict
                            port = $logEvent.port
                            status_code = $logEvent.statuscode
                            querytype = $logEvent.querytype
                            
                            # Egress information
                            egress_ip = $logEvent.egress.ip
                            egress_type = $logEvent.egress.type
                            
                            # User identity fields (flattened)
                            user_name = if ($logEvent.identities -and $logEvent.identities.Count -gt 0) { 
                                ($logEvent.identities | Where-Object { $_.type.type -eq "directory_user" } | Select-Object -First 1).label 
                            } else { $null }
                            user_email = if ($logEvent.identities -and $logEvent.identities.Count -gt 0) { 
                                $userLabel = ($logEvent.identities | Where-Object { $_.type.type -eq "directory_user" } | Select-Object -First 1).label
                                if ($userLabel -match '\(([^)]+)\)') { $matches[1] } else { $null }
                            } else { $null }
                            device_name = if ($logEvent.identities -and $logEvent.identities.Count -gt 0) { 
                                ($logEvent.identities | Where-Object { $_.type.type -eq "anyconnect" } | Select-Object -First 1).label 
                            } else { $null }
                            
                            # Application fields
                            application_name = if ($logEvent.allapplications -and $logEvent.allapplications.Count -gt 0) { 
                                $logEvent.allapplications[0].label 
                            } else { $null }
                            application_category = if ($logEvent.allapplications -and $logEvent.allapplications.Count -gt 0) { 
                                $logEvent.allapplications[0].category.label 
                            } else { $null }
                            
                            # Timestamp fields
                            event_date = $logEvent.date
                            event_time = $logEvent.time
                            event_timestamp = $logEvent.timestamp
                            
                            # Policy and rule fields
                            rule_id = $logEvent.rule.id
                            rule_label = $logEvent.rule.label
                            
                            # Device information
                            device_id = $logEvent.device.id
                            
                            # Data center info
                            datacenter_id = $logEvent.datacenter.id
                            datacenter_label = $logEvent.datacenter.label
                            
                            # Traffic source
                            traffic_source = $logEvent.trafficsource
                            
                            # Raw Cisco fields (fully flattened)
                            returncode = $logEvent.returncode
                            useragent = $logEvent.useragent
                            referer = $logEvent.referer
                            applicationentityname = $logEvent.applicationentityname
                            applicationentitycategory = $logEvent.applicationentitycategory
                            contenttype = $logEvent.contenttype
                            tenantcontrols = $logEvent.tenantcontrols
                            securityoverridden = $logEvent.securityoverridden
                            forwardingmethod = $logEvent.forwardingmethod
                            aimodelname = $logEvent.aimodelname
                            aiscrcategories = if ($logEvent.aiscrcategories) { ($logEvent.aiscrcategories | ForEach-Object { $_.ToString() }) -join ", " } else { $null }
                            requestmethod = $logEvent.requestmethod
                            requestsize = $logEvent.requestsize
                            responsesize = $logEvent.responsesize
                            responsefilename = $logEvent.responsefilename
                            warnstatus = $logEvent.warnstatus
                            sha256 = $logEvent.sha256
                            blockedfiletype = $logEvent.blockedfiletype
                            bundleid = $logEvent.bundleid
                            
                            # Security and threat fields
                            antivirusthreats_puas = if ($logEvent.antivirusthreats -and $logEvent.antivirusthreats.puas) { ($logEvent.antivirusthreats.puas | ForEach-Object { $_.ToString() }) -join ", " } else { $null }
                            antivirusthreats_viruses = if ($logEvent.antivirusthreats -and $logEvent.antivirusthreats.viruses) { ($logEvent.antivirusthreats.viruses | ForEach-Object { $_.ToString() }) -join ", " } else { $null }
                            antivirusthreats_others = if ($logEvent.antivirusthreats -and $logEvent.antivirusthreats.others) { ($logEvent.antivirusthreats.others | ForEach-Object { $_.ToString() }) -join ", " } else { $null }
                            
                            # Data loss prevention
                            datalossprevention_state = $logEvent.datalossprevention.state
                            
                            # Malware Cloud Protection (MCP)
                            mcp_agentid = $logEvent.mcp.agentid
                            mcp_frames = if ($logEvent.mcp -and $logEvent.mcp.frames) { ($logEvent.mcp.frames | ForEach-Object { $_.ToString() }) -join ", " } else { $null }
                            
                            # Cisco AMP fields
                            amp_disposition = $logEvent.amp.disposition
                            amp_score = $logEvent.amp.score
                            amp_malware = $logEvent.amp.malware
                            
                            # Isolation status
                            isolated_state = $logEvent.isolated.state
                            isolated_fileaction = $logEvent.isolated.fileaction
                            
                            # Identities as individual fields (fully expanded)
                            identity_count = if ($logEvent.identities) { $logEvent.identities.Count } else { 0 }
                            identity_ids = if ($logEvent.identities) { ($logEvent.identities | ForEach-Object { $_.id }) -join ", " } else { $null }
                            identity_types = if ($logEvent.identities) { ($logEvent.identities | ForEach-Object { $_.type.type }) -join ", " } else { $null }
                            identity_type_ids = if ($logEvent.identities) { ($logEvent.identities | ForEach-Object { $_.type.id }) -join ", " } else { $null }
                            identity_type_labels = if ($logEvent.identities) { ($logEvent.identities | ForEach-Object { $_.type.label }) -join ", " } else { $null }
                            identity_labels = if ($logEvent.identities) { ($logEvent.identities | ForEach-Object { $_.label }) -join ", " } else { $null }
                            identity_deleted = if ($logEvent.identities) { ($logEvent.identities | ForEach-Object { $_.deleted }) -join ", " } else { $null }
                            
                            # Categories as individual fields (flattened)
                            category_ids = if ($logEvent.categories) { ($logEvent.categories | ForEach-Object { $_.id }) -join ", " } else { $null }
                            category_types = if ($logEvent.categories) { ($logEvent.categories | ForEach-Object { $_.type }) -join ", " } else { $null }
                            category_labels = if ($logEvent.categories) { ($logEvent.categories | ForEach-Object { $_.label }) -join ", " } else { $null }
                            category_integrations = if ($logEvent.categories) { ($logEvent.categories | ForEach-Object { $_.integration }) -join ", " } else { $null }
                            category_deprecated = if ($logEvent.categories) { ($logEvent.categories | ForEach-Object { $_.deprecated }) -join ", " } else { $null }
                            
                            # Applications as individual fields (flattened)
                            allapplications_count = if ($logEvent.allapplications) { $logEvent.allapplications.Count } else { 0 }
                            allapplications_ids = if ($logEvent.allapplications) { ($logEvent.allapplications | ForEach-Object { $_.id }) -join ", " } else { $null }
                            allapplications_labels = if ($logEvent.allapplications) { ($logEvent.allapplications | ForEach-Object { $_.label }) -join ", " } else { $null }
                            allapplications_categories = if ($logEvent.allapplications) { ($logEvent.allapplications | ForEach-Object { $_.category.label }) -join ", " } else { $null }
                            
                            # Blocked applications as individual fields (flattened)
                            blockedapplications_count = if ($logEvent.blockedapplications) { $logEvent.blockedapplications.Count } else { 0 }
                            blockedapplications_ids = if ($logEvent.blockedapplications) { ($logEvent.blockedapplications | ForEach-Object { $_.id }) -join ", " } else { $null }
                            blockedapplications_labels = if ($logEvent.blockedapplications) { ($logEvent.blockedapplications | ForEach-Object { $_.label }) -join ", " } else { $null }
                            
                            # Allowed applications as individual fields (flattened)
                            allowedapplications_count = if ($logEvent.allowedapplications) { $logEvent.allowedapplications.Count } else { 0 }
                            allowedapplications_ids = if ($logEvent.allowedapplications) { ($logEvent.allowedapplications | ForEach-Object { $_.id }) -join ", " } else { $null }
                            allowedapplications_labels = if ($logEvent.allowedapplications) { ($logEvent.allowedapplications | ForEach-Object { $_.label }) -join ", " } else { $null }
                            
                            # Threats as individual fields (flattened)
                            threats_count = if ($logEvent.threats) { $logEvent.threats.Count } else { 0 }
                            threats_ids = if ($logEvent.threats) { ($logEvent.threats | ForEach-Object { $_.id }) -join ", " } else { $null }
                            threats_names = if ($logEvent.threats) { ($logEvent.threats | ForEach-Object { $_.name }) -join ", " } else { $null }
                            
                            # Policy categories as individual fields (flattened)
                            policycategories_count = if ($logEvent.policycategories) { $logEvent.policycategories.Count } else { 0 }
                            policycategories_ids = if ($logEvent.policycategories) { ($logEvent.policycategories | ForEach-Object { $_.id }) -join ", " } else { $null }
                            policycategories_labels = if ($logEvent.policycategories) { ($logEvent.policycategories | ForEach-Object { $_.label }) -join ", " } else { $null }
                            
                            # Destination countries as individual fields (flattened)
                            destinationcountries_count = if ($logEvent.destinationcountries) { $logEvent.destinationcountries.Count } else { 0 }
                            destinationcountries_codes = if ($logEvent.destinationcountries) { ($logEvent.destinationcountries | ForEach-Object { $_.code }) -join ", " } else { $null }
                            destinationcountries_names = if ($logEvent.destinationcountries) { ($logEvent.destinationcountries | ForEach-Object { $_.name }) -join ", " } else { $null }
                            
                            # Destination continents as individual fields (flattened)
                            destinationcontinents_count = if ($logEvent.destinationcontinents) { $logEvent.destinationcontinents.Count } else { 0 }
                            destinationcontinents_codes = if ($logEvent.destinationcontinents) { ($logEvent.destinationcontinents | ForEach-Object { $_.code }) -join ", " } else { $null }
                            destinationcontinents_names = if ($logEvent.destinationcontinents) { ($logEvent.destinationcontinents | ForEach-Object { $_.name }) -join ", " } else { $null }
                }
                $batchPayload += $hecEvent
            }
            
            # Send entire batch in one HTTP request
            $hecHeaders = @{
                "Authorization" = "Splunk $huntressHecToken"
                "Content-Type" = "application/json"
            }
            
            try {
                # Convert each event to JSON and join with newlines for HEC batch format
                $batchJson = ($batchPayload | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress }) -join "`n"
                Invoke-RestMethod -Uri $huntressHecUrl -Headers $hecHeaders -Body $batchJson -Method Post | Out-Null
                $successCount += $batchEvents.Count
                Write-Host "✓ Batch $($batchIndex + 1): Successfully sent $($batchEvents.Count) events"
            }
            catch {
                $errorCount += $batchEvents.Count
                Write-Warning "Failed to send batch $($batchIndex + 1): $($_.Exception.Message)"
            }
        }
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        Write-Host "Log shipping completed. Success: $successCount, Errors: $errorCount"
        Write-Host "Processing time: $($duration.TotalSeconds.ToString('F2')) seconds"
        Write-Host "Average rate: $([math]::Round($successCount / $duration.TotalSeconds, 2)) events/second"
        Write-Host "Performance improvement: $([math]::Round(($logs.Count / $duration.TotalSeconds) / ($logs.Count / 240), 2))x faster than sequential"
        
        # Return success response for Azure Function
        return @{
            StatusCode = 200
            Body = @{
                message = "Log shipping completed successfully"
                successCount = $successCount
                errorCount = $errorCount
                processingTimeSeconds = $duration.TotalSeconds
                averageRatePerSecond = [math]::Round($successCount / $duration.TotalSeconds, 2)
                performanceImprovement = [math]::Round(($logs.Count / $duration.TotalSeconds) / ($logs.Count / 240), 2)
            } | ConvertTo-Json
        }
    }
    else {
        Write-Host "No log data received from Cisco Umbrella."
        return @{
            StatusCode = 200
            Body = @{
                message = "No log data received from Cisco Umbrella"
                successCount = 0
                errorCount = 0
            } | ConvertTo-Json
        }
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    return @{
        StatusCode = 500
        Body = @{
            error = $_.Exception.Message
        } | ConvertTo-Json
    }
}