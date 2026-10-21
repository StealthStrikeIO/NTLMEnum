"""
Comprehensive NTLM endpoint path wordlist.

Organized by technology/product to make maintenance clear.
Each entry is a tuple of (path, category) for reporting.
"""

NTLM_PATHS: list[tuple[str, str]] = [
    # === Microsoft Exchange ===
    ("/autodiscover", "Exchange"),
    ("/autodiscover/autodiscover.xml", "Exchange"),
    ("/Autodiscover/Autodiscover.xml", "Exchange"),
    ("/ecp/", "Exchange"),
    ("/ecp/default.aspx", "Exchange"),
    ("/ews/", "Exchange"),
    ("/EWS/Exchange.asmx", "Exchange"),
    ("/exchange/", "Exchange"),
    ("/Exchweb/", "Exchange"),
    ("/mapi/nspi/", "Exchange"),
    ("/mapi/emsmdb/", "Exchange"),
    ("/Microsoft-Server-ActiveSync/", "Exchange"),
    ("/OAB/", "Exchange"),
    ("/oab/default.aspx", "Exchange"),
    ("/owa/", "Exchange"),
    ("/owa/auth/logon.aspx", "Exchange"),
    ("/PowerShell/", "Exchange"),
    ("/Rpc/", "Exchange"),
    ("/RpcWithCert/", "Exchange"),
    ("/UnifiedMessaging/", "Exchange"),

    # === SharePoint ===
    ("/_vti_bin/", "SharePoint"),
    ("/_vti_bin/shtml.dll", "SharePoint"),
    ("/_vti_bin/owssvr.dll", "SharePoint"),
    ("/_vti_bin/Lists.asmx", "SharePoint"),
    ("/_vti_bin/Webs.asmx", "SharePoint"),
    ("/_layouts/", "SharePoint"),
    ("/_layouts/viewlsts.aspx", "SharePoint"),
    ("/_layouts/15/start.aspx", "SharePoint"),
    ("/_api/web/", "SharePoint"),
    ("/_windows/default.aspx", "SharePoint"),

    # === ADFS / SSO ===
    ("/adfs/ls/", "ADFS"),
    ("/adfs/ls/wia", "ADFS"),
    ("/adfs/services/trust/2005/windowstransport", "ADFS"),
    ("/adfs/services/trust/13/windowstransport", "ADFS"),
    ("/iwa/authenticated.aspx", "ADFS"),
    ("/iwa/iwa_test.aspx", "ADFS"),
    ("/sso/", "ADFS"),

    # === Skype for Business / Lync ===
    ("/abs/", "Skype/Lync"),
    ("/Autodiscover/AutodiscoverService.svc/root", "Skype/Lync"),
    ("/AutoUpdate/", "Skype/Lync"),
    ("/Conf/", "Skype/Lync"),
    ("/deviceupdatefiles_ext/", "Skype/Lync"),
    ("/deviceupdatefiles_int/", "Skype/Lync"),
    ("/dialin", "Skype/Lync"),
    ("/GroupExpansion/", "Skype/Lync"),
    ("/HybridConfig/", "Skype/Lync"),
    ("/mcx/", "Skype/Lync"),
    ("/meet/", "Skype/Lync"),
    ("/PersistentChat/", "Skype/Lync"),
    ("/PhoneConferencing/", "Skype/Lync"),
    ("/Reach/sip.svc", "Skype/Lync"),
    ("/RequestHandler/", "Skype/Lync"),
    ("/RequestHandlerExt/", "Skype/Lync"),
    ("/RequestHandlerExt/GenericRecordsSvc.svc", "Skype/Lync"),
    ("/Rgs/", "Skype/Lync"),
    ("/RgsClients/", "Skype/Lync"),
    ("/scheduler/", "Skype/Lync"),
    ("/Ucwa/", "Skype/Lync"),
    ("/WebTicket/", "Skype/Lync"),
    ("/WebTicket/WebTicketService.svc", "Skype/Lync"),

    # === Certificate Services ===
    ("/certsrv/", "ADCS"),
    ("/CertSrv/", "ADCS"),
    ("/CertEnroll/", "ADCS"),
    ("/CertProv/", "ADCS"),
    ("/ocsp/", "ADCS"),

    # === RD Web Access / RD Gateway ===
    ("/RDWeb/", "RDWeb"),
    ("/RDWeb/Pages/en-US/login.aspx", "RDWeb"),
    ("/rpc/rpcproxy.dll", "RDWeb"),

    # === SCCM / MECM / WSUS ===
    ("/ccm_system_windowsauth/request", "SCCM"),
    ("/SMS_DP_SMSPKG$/", "SCCM"),
    ("/SMS_DP_SMSSIG$/", "SCCM"),
    ("/CMUserService_WindowsAuth/", "SCCM"),
    ("/CMApplicationCatalog/", "SCCM"),
    ("/selfservice/", "WSUS"),
    ("/ClientWebService/client.asmx", "WSUS"),
    ("/SimpleAuthWebService/SimpleAuth.asmx", "WSUS"),
    ("/DssAuthWebService/DssAuth.asmx", "WSUS"),
    ("/ServerSyncWebService/ServerSync.asmx", "WSUS"),
    ("/ApiRemoting30/", "WSUS"),

    # === IIS / Generic Windows ===
    ("/", "Generic"),
    ("/aspnet_client/", "IIS"),
    ("/api/", "IIS"),
    ("/remote/", "IIS"),
    ("/Reports/", "SSRS"),
    ("/ReportServer/", "SSRS"),
    ("/reportserver/", "SSRS"),
    ("/tfs/", "TFS/AzDO"),
    ("/DefaultCollection/", "TFS/AzDO"),

    # === WSMAN / WinRM ===
    ("/wsman", "WinRM"),
    ("/wsman/", "WinRM"),

    # === Outlook Anywhere / MAPI over HTTP ===
    ("/rpc/rpcproxy.dll", "OutlookAnywhere"),
    ("/mapi/nspi", "MAPI"),
    ("/mapi/emsmdb", "MAPI"),

    # === Microsoft Dynamics / CRM ===
    ("/XRMServices/2011/Organization.svc", "Dynamics"),
    ("/api/data/", "Dynamics"),

    # === SCOM ===
    ("/OperationsManager/", "SCOM"),

    # === Backup / DPM ===
    ("/DPM/", "DPM"),

    # === Miscellaneous ===
    ("/debug/", "Debug"),
    ("/Etc/", "Misc"),
    ("/Public/", "Misc"),
]

# Deduplicate while preserving order
_seen: set[str] = set()
UNIQUE_PATHS: list[tuple[str, str]] = []
for path, cat in NTLM_PATHS:
    normalized = path.lower()
    if normalized not in _seen:
        _seen.add(normalized)
        UNIQUE_PATHS.append((path, cat))

NTLM_PATHS = UNIQUE_PATHS
del _seen, UNIQUE_PATHS
