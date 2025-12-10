# =============================================================================
# Project: Active Directory HTML Report Generator (Dashboard)
# Author: Kasim Aytan
# Description: Generates a standalone HTML dashboard for AD User Analysis.
# Features: Stale Account Detection, Admin Discovery, Password Aging, Usage Stats.
# License: MIT License (Open Source)
# =============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# --- 1. AUTOMATIC DOMAIN DETECTION ---
try {
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domainObj.Name
    $domainDN = "DC=" + $domainName.Replace(".", ",DC=")
} catch {
    Write-Warning "Error: Not connected to a Domain network."
    return
}

# --- CONSOLE UI ---
Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   ACTIVE DIRECTORY ANALYSIS TOOL | $domainName" -ForegroundColor White
Write-Host "   ------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "   [+] Scanning User Objects & Group Memberships..." -ForegroundColor Yellow
Write-Host "   [+] Analyzing Account Usage & Security Flags..." -ForegroundColor Yellow
Write-Host "   [+] Generating HTML Dashboard..." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan

# --- 2. DATA COLLECTION ---
try {
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.SearchRoot = "LDAP://$domainDN"
    $searcher.PageSize = 5000 
    
    # Properties to fetch
    $properties = @("samaccountname", "displayname", "mail", "department", "useraccountcontrol", "lastlogontimestamp", "pwdlastset", "msDS-UserPasswordExpiryTimeComputed", "givenname", "sn", "telephoneNumber", "title", "whenCreated", "memberOf", "manager", "lockoutTime", "description", "primaryGroupID")
    foreach ($prop in $properties) { [void]$searcher.PropertiesToLoad.Add($prop) }
    
    $results = $searcher.FindAll()
    
    # Counters
    $totalUsers = 0; $realActiveUsers = 0; $staleUsers = 0; $expiredPasswordUsers = 0; $neverLoggedIn = 0; $lockedAccounts = 0
    
    $userList = New-Object System.Collections.Generic.List[Object]
    $Today = Get-Date

    foreach ($result in $results) {
        $p = $result.Properties
        $sam = if ($p.samaccountname) { $p.samaccountname[0] } else { "" }
        
        # Filter System/Exchange Accounts
        if ($sam -like "HealthMailbox*" -or $sam -like "SM_*" -or $sam -like "MSOL_*") { continue }

        $totalUsers++
        
        $disp = if ($p.displayname) { $p.displayname[0] } else { $sam }
        $mail = if ($p.mail) { $p.mail[0] } else { "" }
        $dept = if ($p.department) { $p.department[0] } else { "Unknown" }
        $title = if ($p.title) { $p.title[0] } else { "" }
        $desc = if ($p.description) { $p.description[0] } else { "" }
        
        $mgrRaw = if ($p.manager) { $p.manager[0] } else { "" }
        $mgr = if ($mgrRaw) { ($mgrRaw -split ",")[0].Replace("CN=", "") } else { "-" }

        $uac = if ($p.useraccountcontrol) { [int]$p.useraccountcontrol[0] } else { 512 }
        $isEnabled = ($uac -band 2) -eq 0 
        
        $isLocked = $false
        if ($p.lockoutTime -and $p.lockoutTime[0] -gt 0) { $isLocked = $true; $lockedAccounts++ }

        # --- LOGON ANALYSIS ---
        $lastLogon = "Never Logged In"; $daysLogonStr = "-"; $diff = 99999
        $usageStatus = "Never Logged In"
        
        if ($p.lastlogontimestamp -and $p.lastlogontimestamp[0] -gt 0) {
            try { 
                $d = [DateTime]::FromFileTime($p.lastlogontimestamp[0])
                # Fix for future dates (AD Bug 2093, etc.)
                if ($d.Year -gt ($Today.Year + 5)) { 
                    $lastLogon = "-"; $daysLogonStr = "-"
                    $usageStatus = "Active (System)"
                } else {
                    $lastLogon = $d.ToString("dd.MM.yyyy HH:mm")
                    $diff = ($Today - $d).Days
                    if ($diff -lt 0) { $daysLogonStr = "-" } else { $daysLogonStr = "$diff days" }

                    if ($diff -le 60) { 
                        $usageStatus = "Active PC"
                        if ($isEnabled) { $realActiveUsers++ } 
                    } elseif ($diff -le 180) { 
                        $usageStatus = "Infrequent" 
                    } else { 
                        $usageStatus = "Stale"
                        if ($isEnabled) { $staleUsers++ } 
                    }
                }
            } catch {}
        } else { 
            $neverLoggedIn++
            $usageStatus = "Never Logged In" 
        }

        $durum = if ($isLocked) { "Locked" } elseif ($isEnabled) { "Enabled" } else { "Disabled" }
        
        # --- PASSWORD ANALYSIS ---
        $pwdStatus = "Valid"; $pwdClass = "success"; $isExpired = $false
        if ($p.'msds-userpasswordexpirytimecomputed' -and $p.'msds-userpasswordexpirytimecomputed'[0]) {
            try { if ([DateTime]::FromFileTime($p.'msds-userpasswordexpirytimecomputed'[0]) -lt $Today) { $isExpired = $true } } catch {}
        }
        if ($isExpired) { $pwdStatus = "Expired"; $pwdClass = "danger"; $expiredPasswordUsers++ }
        
        $created = ""; if ($p.whenCreated) { try { $created = ([DateTime]::Parse($p.whenCreated[0].ToString())).ToString("dd.MM.yyyy") } catch {} }

        # --- ADMIN CHECK (Recursive & Primary Group) ---
        $isAdmin = $false
        $allGroups = @()
        
        # Primary Group ID 512 = Domain Admins
        $primID = if ($p.primaryGroupID) { $p.primaryGroupID[0] } else { 0 }
        if ($primID -eq 512) { $isAdmin = $true; $allGroups += "Domain Admins" }

        if ($p.memberOf) {
            foreach ($g in $p.memberOf) {
                $gName = ($g -split ",")[0].Replace("CN=", "")
                $allGroups += $gName
                if ($gName -match "Admin" -or $gName -eq "Domain Admins" -or $gName -eq "Enterprise Admins") { $isAdmin = $true }
            }
        }
        $fullGroupsStr = $allGroups -join "|" 

        $userList.Add([PSCustomObject]@{
            Sira = $totalUsers; AdSoyad = $disp; KullaniciAdi = $sam; Eposta = $mail; Departman = $dept; Unvan = $title; Yonetici = $mgr;
            Durum = $durum; Kullanim = $usageStatus;
            ParolaDurumu = $pwdStatus; ParolaClass = $pwdClass; 
            SonGiris = $lastLogon; GunOnce = $daysLogonStr;
            IsAdmin = $isAdmin; Aciklama = $desc; Olusturulma = $created;
            TumGruplar = $fullGroupsStr
        })
    }

    $groupedDept = $userList | Group-Object Departman | Sort-Object Count -Descending 
    $deptLabels = @($groupedDept | ForEach-Object { $_.Name })
    $deptCounts = @($groupedDept | ForEach-Object { [int]$_.Count })

    $jsonData = $userList | ConvertTo-Json -Depth 2 -Compress
    $statsData = @{ Total=$totalUsers; RealActive=$realActiveUsers; Stale=$staleUsers; Never=$neverLoggedIn; Locked=$lockedAccounts; Expired=$expiredPasswordUsers; Domain=$domainName; DL=$deptLabels; DC=$deptCounts }
    $statsJson = $statsData | ConvertTo-Json -Depth 5 -Compress 
    $utf8 = [System.Text.Encoding]::UTF8
    $b64Data = [Convert]::ToBase64String($utf8.GetBytes($jsonData))
    $b64Stats = [Convert]::ToBase64String($utf8.GetBytes($statsJson))

# HTML Template
$html = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Analysis Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        :root { --bg: #f8fafc; --text: #334155; --primary: #4f46e5; }
        body { background-color: var(--bg); font-family: 'Inter', sans-serif; color: var(--text); font-size: 0.8rem; }
        
        .navbar { background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.05); padding: 0.4rem 1.5rem; }
        .brand { font-weight: 700; color: var(--primary); font-size: 1rem; }

        .stat-card {
            background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 10px 12px;
            cursor: pointer; transition: 0.2s; position: relative; overflow: hidden; height: 100%;
            display: flex; flex-direction: column; justify-content: space-between;
        }
        .stat-card:hover { border-color: var(--primary); transform: translateY(-2px); box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .stat-card.active { background: #eef2ff; border-color: var(--primary); }
        
        .stat-label { 
            font-size: 0.6rem; font-weight: 700; text-transform: uppercase; color: #64748b; margin-bottom: 2px; letter-spacing: 0.5px;
        }
        .stat-val { 
            font-size: 1.4rem; font-weight: 700; color: #1e293b; line-height: 1;
        }
        .stat-icon { 
            position: absolute; right: 10px; top: 50%; transform: translateY(-50%); 
            font-size: 1.8rem; opacity: 0.12; color: #334155;
        }
        
        .sc-blue { border-left: 3px solid #3b82f6; } .sc-green { border-left: 3px solid #22c55e; } 
        .sc-gray { border-left: 3px solid #94a3b8; } .sc-red { border-left: 3px solid #ef4444; }
        .sc-purple { border-left: 3px solid #a855f7; } .sc-dark { border-left: 3px solid #334155; }

        .chart-card { background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 10px 15px; height: 100%; }
        .chart-header { font-size: 0.8rem; font-weight: 600; margin-bottom: 5px; color: #475569; }
        .chart-wrapper { position: relative; height: 180px; } 
        .chart-scroll { overflow-y: auto; height: 100%; padding-right: 5px; }

        .table-card { background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 12px; margin-top: 0.8rem; }
        
        table.dataTable { border-collapse: collapse !important; width: 100% !important; margin-top: 0 !important; }
        table.dataTable thead th { 
            background: #f1f5f9; font-weight: 600; font-size: 0.7rem; 
            padding: 6px 8px !important; border-bottom: 1px solid #e2e8f0; white-space: nowrap; 
        }
        table.dataTable tbody td { 
            padding: 4px 8px !important; vertical-align: middle; font-size: 0.75rem; border-bottom: 1px solid #f1f5f9;
        }
        
        .txt-trunc { max-width: 130px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: block; }
        .td-nowrap { white-space: nowrap; }

        .badge-s { padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 600; white-space: nowrap; }
        .bg-ok { background: #dcfce7; color: #166534; } .bg-warn { background: #ffedd5; color: #9a3412; } 
        .bg-err { background: #fee2e2; color: #991b1b; } .bg-ghost { background: #f1f5f9; color: #64748b; border: 1px solid #cbd5e1; }

        .row-stale { opacity: 0.6; background-color: #fafafa !important; } .row-stale:hover { opacity: 1; }

        .form-control-sm-custom { height: 24px; padding: 1px 5px; font-size: 0.7rem; border: 1px solid #cbd5e1; border-radius: 4px; width: 100%; }
        .dataTables_length select { font-size: 0.75rem; padding: 1px 5px; } .dataTables_length { font-size: 0.75rem; color: #64748b; margin-bottom: 5px; }
        div.dataTables_info { font-size: 0.75rem; color: #64748b; }

        .pie-center-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; pointer-events: none; }
        .pie-val { font-size: 1.8rem; font-weight: 800; color: #334155; line-height: 1; }
        
        .admin-row { background-color: rgba(245, 158, 11, 0.08) !important; }
        .modal-content { border: 1px solid #e2e8f0; }
        .group-badge { display: inline-block; background: var(--primary); color: white; padding: 2px 6px; border-radius: 4px; margin: 2px; font-size: 0.7rem; }
    </style>
</head>
<body>

    <nav class="navbar fixed-top">
        <div class="d-flex align-items-center gap-2">
            <i class="fa-brands fa-microsoft text-primary fs-5"></i>
            <span class="brand" id="pageTitle">AD Analysis Dashboard</span>
        </div>
        <div class="small text-muted" id="headerInfo" style="font-size: 0.75rem;">Loading...</div>
    </nav>
    <div style="height: 50px;"></div>

    <div class="container-fluid px-4 py-2">
        
        <div class="row g-2 mb-2">
            <div class="col-xl-2 col-md-4 col-6"><div class="stat-card sc-blue clickable" data-col="all"><div class="stat-label">Total Accounts</div><div class="stat-val" id="vTotal">0</div><i class="fa-solid fa-users stat-icon"></i></div></div>
            <div class="col-xl-2 col-md-4 col-6"><div class="stat-card sc-green clickable" data-col="Kullanim" data-val="Active PC"><div class="stat-label text-success">Active Users</div><div class="stat-val text-success" id="vReal">0</div><i class="fa-solid fa-desktop stat-icon"></i></div></div>
            <div class="col-xl-2 col-md-4 col-6"><div class="stat-card sc-gray clickable" data-col="Kullanim" data-val="Stale"><div class="stat-label text-muted">Stale (6 Mo+)</div><div class="stat-val text-muted" id="vStale">0</div><i class="fa-solid fa-bed stat-icon"></i></div></div>
            <div class="col-xl-2 col-md-4 col-6"><div class="stat-card sc-red clickable" data-col="ParolaDurumu" data-val="Expired"><div class="stat-label text-danger">Pwd Expired</div><div class="stat-val text-danger" id="vExpired">0</div><i class="fa-solid fa-key stat-icon"></i></div></div>
            <div class="col-xl-2 col-md-4 col-6"><div class="stat-card sc-purple clickable" data-col="SonGiris" data-val="Never Logged In"><div class="stat-label">Never Logged In</div><div class="stat-val" id="vNever">0</div><i class="fa-solid fa-ghost stat-icon"></i></div></div>
            <div class="col-xl-2 col-md-4 col-6"><div class="stat-card sc-dark clickable" data-col="Durum" data-val="Locked"><div class="stat-label">Locked</div><div class="stat-val" id="vLocked">0</div><i class="fa-solid fa-lock stat-icon"></i></div></div>
        </div>

        <div class="row g-2">
            <div class="col-lg-8">
                <div class="chart-card">
                    <div class="chart-header">
                        <span><i class="fa-solid fa-chart-bar me-1"></i> Department Distribution</span>
                        <small class="text-muted fw-normal">(Scrollable)</small>
                    </div>
                    <div class="chart-wrapper">
                        <div class="chart-scroll">
                            <div style="position: relative; height: 1000px; width: 100%">
                                <canvas id="deptChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="chart-card">
                    <div class="chart-header"><span><i class="fa-solid fa-chart-pie me-1"></i> Real Usage Ratio</span></div>
                    <div class="chart-wrapper d-flex align-items-center justify-content-center position-relative">
                        <div style="width: 100%; height: 180px;">
                            <canvas id="statusChart"></canvas>
                        </div>
                        <div class="pie-center-text">
                            <div class="pie-val" id="centerTotal">-</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-card">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <h6 class="m-0 fw-bold" style="color: var(--text); font-size: 0.9rem;"><i class="fa-solid fa-list me-2"></i>User List</h6>
                <div>
                    <button class="btn btn-sm btn-outline-success py-0 px-2" style="font-size: 0.7rem;" id="btnXls">Excel</button>
                    <button class="btn btn-sm btn-outline-secondary py-0 px-2" style="font-size: 0.7rem;" id="btnRst">Reset</button>
                </div>
            </div>
            
            <table id="mainTable" class="table table-hover table-sm w-100">
                <thead>
                    <tr><th>#</th><th>Name</th><th>Manager</th><th>Username</th><th>Department</th><th>Title</th><th>Status</th><th>Usage</th><th>Password</th><th>Last Logon</th><th>Days</th></tr>
                    <tr class="filter-row">
                        <th></th>
                        <th><input type="text" class="form-control-sm-custom" placeholder="Search..."></th>
                        <th><input type="text" class="form-control-sm-custom" placeholder="Search..."></th>
                        <th><input type="text" class="form-control-sm-custom" placeholder="Search..."></th>
                        <th><input type="text" class="form-control-sm-custom" placeholder="Search..."></th>
                        <th><input type="text" class="form-control-sm-custom" placeholder="Search..."></th>
                        <th><select class="form-control-sm-custom"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option></select></th>
                        <th>
                            <select class="form-control-sm-custom">
                                <option value="">All</option>
                                <option value="Active PC">Active PC</option>
                                <option value="Infrequent">Infrequent</option>
                                <option value="Stale">Stale</option>
                                <option value="Never Logged In">Never</option>
                            </select>
                        </th>
                        <th><select class="form-control-sm-custom"><option value="">All</option><option value="Valid">Valid</option><option value="Expired">Expired</option></select></th>
                        <th><input type="text" class="form-control-sm-custom" placeholder="Date..."></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody id="tBody"></tbody>
            </table>
        </div>
        <div class="text-center text-muted mt-2" style="font-size: 0.65rem;">Generated by AD Analysis Tool • Author: Kasim Aytan</div>
    </div>

    <div class="modal fade" id="userModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered modal-lg">
            <div class="modal-content">
                <div class="modal-header py-2">
                    <h6 class="modal-title fw-bold" id="mName"></h6>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row g-2">
                        <div class="col-6"><div class="detail-label">Username</div><div class="small" id="mUser">-</div></div>
                        <div class="col-6"><div class="detail-label">Title</div><div class="small" id="mTitle">-</div></div>
                        <div class="col-6"><div class="detail-label">Email</div><div class="small" id="mMail">-</div></div>
                        <div class="col-6"><div class="detail-label">Manager</div><div class="small" id="mManager">-</div></div>
                        <div class="col-6"><div class="detail-label">Created</div><div class="small" id="mCreated">-</div></div>
                        <div class="col-6"><div class="detail-label">Last Logon</div><div class="small" id="mLastLogon">-</div></div>
                        <div class="col-12"><div class="detail-label">Description</div><div class="small" id="mDesc">-</div></div>
                        <div class="col-12"><div class="detail-label">Groups</div><div id="mGroups">-</div></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.3.6/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.3.6/js/buttons.html5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <script>
        function dec(s) { return new TextDecoder().decode(Uint8Array.from(atob(s), c => c.codePointAt(0))); }
        let usersData = [];

        function showDetail(index) {
            let u = usersData[index];
            $('#mName').html(u.AdSoyad); $('#mUser').text(u.KullaniciAdi); $('#mTitle').text(u.Unvan);
            $('#mMail').text(u.Eposta); $('#mManager').text(u.Yonetici); $('#mCreated').text(u.Olusturulma);
            $('#mLastLogon').text(u.SonGiris); $('#mDesc').text(u.Aciklama);
            let grps = u.TumGruplar.split('|');
            let grpHtml = grps.length > 0 && grps[0] !== "" ? grps.map(g => `<span class="group-badge">${g}</span>`).join('') : '-';
            $('#mGroups').html(grpHtml);
            new bootstrap.Modal(document.getElementById('userModal')).show();
        }

        $(document).ready(function() {
            try {
                const stats = JSON.parse(dec('@BASE64_STATS@'));
                usersData = JSON.parse(dec('@BASE64_DATA@'));

                $('#pageTitle').text(stats.Domain + ' Dashboard');
                $('#headerInfo').text(`Generated: ${new Date().toLocaleDateString()}`);
                
                $('#vTotal').text(stats.Total); 
                $('#vReal').text(stats.RealActive || 0);
                $('#vStale').text(stats.Stale || 0); 
                $('#vNever').text(stats.Never || 0);
                $('#vExpired').text(stats.Expired); $('#vLocked').text(stats.Locked);
                $('#centerTotal').text(stats.Total);

                // CHART 1: DEPT
                const chartH = Math.max(300, stats.DL.length * 20);
                $('#deptChart').parent().height(chartH);
                new Chart(document.getElementById('deptChart'), {
                    type: 'bar',
                    data: { labels: stats.DL, datasets: [{ label: 'Users', data: stats.DC, backgroundColor: '#6366f1', borderRadius: 3, barThickness: 8 }] },
                    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: {display:false} }, scales: { x: { display:false }, y: { grid: {display:false}, ticks: {font:{size:9}} } }, onClick: (e, el) => { if(el.length) filterTable(4, stats.DL[el[0].index]); }, onHover: (e, el) => e.native.target.style.cursor = el[0] ? 'pointer' : 'default' }
                });

                // CHART 2: USAGE
                new Chart(document.getElementById('statusChart'), {
                    type: 'doughnut',
                    data: { labels: ['Active PC', 'Stale', 'Never Logged In'], datasets: [{ data: [stats.RealActive, stats.Stale, stats.Never], backgroundColor: ['#22c55e', '#94a3b8', '#a855f7'], borderWidth: 0 }] },
                    options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: {display:false} }, onClick: (e, el) => { if(el.length) filterTable(7, ['Active PC', 'Stale', 'Never Logged In'][el[0].index]); }, onHover: (e, el) => e.native.target.style.cursor = el[0] ? 'pointer' : 'default' }
                });

                // TABLE
                const rows = usersData.map((u, i) => {
                    let accCls = u.Durum==='Enabled'?'bg-ok':(u.Durum==='Locked'?'bg-err':'bg-warn');
                    let pwdCls = u.ParolaDurumu==='Valid'?'bg-ok':'bg-err';
                    let useCls = 'bg-ghost';
                    if(u.Kullanim === 'Active PC') useCls = 'bg-ok'; else if(u.Kullanim === 'Infrequent') useCls = 'bg-warn';
                    let logSt = u.SonGiris.includes('Never')?'text-danger fw-bold':'';
                    let adminIcon = u.IsAdmin ? '<i class="fa-solid fa-crown text-warning me-1" title="Admin"></i>' : '';
                    let adminRow = u.IsAdmin ? 'admin-row' : '';
                    let staleRow = (u.Kullanim.includes('Stale') || u.Kullanim.includes('Never')) ? 'row-stale' : '';
                    
                    return `<tr class="${adminRow} ${staleRow}">
                        <td class="text-muted">${u.Sira}</td>
                        <td class="fw-bold clickable" style="color:#4f46e5" onclick="showDetail(${i})">${adminIcon}${u.AdSoyad}</td>
                        <td><div class="txt-trunc" title="${u.Yonetici}">${u.Yonetici}</div></td>
                        <td>${u.KullaniciAdi}</td>
                        <td><div class="txt-trunc" title="${u.Departman}">${u.Departman}</div></td>
                        <td><div class="txt-trunc" title="${u.Unvan}">${u.Unvan}</div></td>
                        <td><span class="badge-s ${accCls}">${u.Durum}</span></td>
                        <td><span class="badge-s ${useCls}">${u.Kullanim}</span></td>
                        <td><span class="badge-s ${pwdCls}">${u.ParolaDurumu}</span></td>
                        <td class="${logSt} td-nowrap">${u.SonGiris}</td>
                        <td class="text-muted td-nowrap">${u.GunOnce}</td>
                    </tr>`;
                }).join('');
                $('#tBody').html(rows);

                // GENERIC SEARCH LOGIC (No special Turkish handling needed for English output)
                const table = $('#mainTable').DataTable({ 
                    dom: '<"d-flex justify-content-between align-items-center"l>rtip', 
                    pageLength: 25, 
                    lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]], 
                    buttons:[{extend:'excelHtml5',className:'d-none'}], 
                });

                function filterTable(c, v) { 
                    table.search('').columns().search('').draw(); 
                    $('.filter-row input, .filter-row select').val(''); 
                    if(v && v!=='all') {
                        if(c === 6 || c === 7 || c === 8) {
                             table.column(c).search('^' + v, true, false).draw(); 
                        } else {
                             table.column(c).search(v).draw(); 
                        }
                    }
                    $('html, body').animate({ scrollTop: $(".table-card").offset().top - 80 }, 400); 
                }

                $('.stat-card').click(function(){ 
                    $('.stat-card').removeClass('active'); $(this).addClass('active'); 
                    // Map generic column names
                    let colName = $(this).data('col');
                    let filterVal = $(this).data('val');
                    let colIdx = 0;
                    if(colName === 'Durum') colIdx = 6;
                    else if(colName === 'Kullanim') colIdx = 7;
                    else if(colName === 'ParolaDurumu') colIdx = 8;
                    else if(colName === 'SonGiris') colIdx = 9;

                    filterTable(colIdx, filterVal || (colName==='all'?'all':'')); 
                });
                
                $('#mainTable thead input, #mainTable thead select').on('keyup change', function() { let i = $(this).parent().index(); if(table.column(i).search()!==this.value) table.column(i).search(this.value).draw(); });
                $('#btnXls').click(()=>table.button('.buttons-excel').trigger());
                $('#btnRst').click(()=>{ filterTable(0,'all'); $('.stat-card').removeClass('active'); });

            } catch(e) { alert("Data Load Error!"); }
        });
    </script>
</body>
</html>
'@

    $html = $html.Replace('@BASE64_STATS@', $b64Stats).Replace('@BASE64_DATA@', $b64Data)
    # Generic Filename
    $DateStr = Get-Date -Format "dd-MM-yyyy"
    $path = "$([Environment]::GetFolderPath('Desktop'))\AD_Analysis_Report_$DateStr.html"
    [System.IO.File]::WriteAllText($path, $html, [System.Text.UTF8Encoding]::new($true))
    Write-Host "Report generated: $path" -ForegroundColor Green

} catch { Write-Host "Error: $_" -f Red }