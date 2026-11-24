; UBADS Windows Endpoint Agent - Inno Setup installer script.
;
; Phase 17 / Stage 4E: the installer enrolls the computer using the one-time code carried
; by its own file name (UBADS-Agent-Setup--<code>.exe, produced by the UBADS portal) and then
; schedules and starts the background agent. See docs/phase17-stage4e-installer.md.
;
; HOW THE CODE IS HANDLED: this script never reads, stores, logs or forwards the code. It passes
; its OWN PROCESS ID to "ubads-agent.exe --enroll-from-process <pid>"; the agent checks that the id
; belongs to an ancestor of itself and reads the code from that process's executable file name.
; Nothing goes on a command line, in an environment variable, a temp file, a config file, a log
; or the registry.
;
; BUILD VARIANTS (compile with ISCC):
;   (none)                   production installer           -> ..\dist\UBADS-Agent-Setup.exe
;   /DTESTBUILD              isolated per-user TEST installer (no UAC)  -> ..\dist-test\...
;   /DTESTBUILD_ELEVATED     isolated TEST installer that DOES request UAC (for the manual
;                            elevation check)                           -> ..\dist-test\...
;   /DDistDir=..\dist-test   where the agent executables come from (default ..\dist)
; The TEST variants use their own AppId, folders, state directory and scheduled-task name, so
; they can never touch an installed production agent. NOT code-signed in any variant.

#define MyAppName "UBADS Windows Endpoint Agent"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "UBADS project (local/dev build - not a signed release)"
#define MyAppExeName "ubads-agent.exe"

#ifndef DistDir
  #define DistDir "..\dist"
#endif
#ifdef TESTBUILD_ELEVATED
  #ifndef TESTBUILD
    #define TESTBUILD
  #endif
#endif

#ifdef TESTBUILD_ELEVATED
  #define ElevatedBuildLiteral "True"
#else
  #define ElevatedBuildLiteral "False"
#endif

[Setup]
#ifdef TESTBUILD
AppId={{7A3D2C10-5E4B-4C1A-9B0F-2D6E8A1C7F42}
AppName={#MyAppName} [TEST BUILD]
DefaultGroupName=UBADS Agent TEST
OutputDir=..\dist-test
  #ifdef TESTBUILD_ELEVATED
DefaultDirName={autopf}\UBADS Agent TEST
PrivilegesRequired=admin
OutputBaseFilename=UBADS-Agent-Setup-TEST-ELEVATED
  #else
DefaultDirName={localappdata}\UBADS-TEST\App
PrivilegesRequired=lowest
OutputBaseFilename=UBADS-Agent-Setup-TEST
  #endif
InfoBeforeFile=before-install-test.txt
#else
AppId={{CBBE64B3-E934-4A0A-965A-020FB03784DD}
AppName={#MyAppName}
DefaultGroupName=UBADS Agent
DefaultDirName={autopf}\UBADS Agent
; Administrator rights are needed to install into Program Files and to read the Windows Security
; log. Windows asks for this through its normal UAC prompt - it is never bypassed.
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=UBADS-Agent-Setup
InfoBeforeFile=before-install.txt
#endif
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DisableProgramGroupPage=yes
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
; Deliberately no SetupLogging: Inno's optional /LOG switch records the setup file's path, and that
; path carries the one-time enrollment code.
SetupLogging=no
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
#ifdef TESTBUILD
Name: "{localappdata}\UBADS-TEST\Agent"; Permissions: users-modify
Name: "{localappdata}\UBADS-TEST\Agent\config"; Permissions: users-modify
Name: "{localappdata}\UBADS-TEST\Agent\state"; Permissions: users-modify
Name: "{localappdata}\UBADS-TEST\Agent\logs"; Permissions: users-modify
#else
Name: "{commonappdata}\UBADS"; Permissions: admins-full system-full
Name: "{commonappdata}\UBADS\Agent"; Permissions: admins-full system-full
Name: "{commonappdata}\UBADS\Agent\config"; Permissions: admins-full system-full
Name: "{commonappdata}\UBADS\Agent\state"; Permissions: admins-full system-full
Name: "{commonappdata}\UBADS\Agent\logs"; Permissions: admins-full system-full
#endif

[Files]
Source: "{#DistDir}\ubads-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#DistDir}\ubads-agent-bg.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\UBADS Agent Status"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--verify-enrollment --require-running"; WorkingDir: "{app}"
Name: "{group}\Open Installation Folder"; Filename: "{app}"
Name: "{group}\Uninstall UBADS Agent"; Filename: "{uninstallexe}"

[UninstallRun]
; Stop the agent and remove its scheduled task before the files are deleted. The endpoint's
; identity/credential stay on disk (a later reinstall keeps its identity); an administrator should
; revoke the endpoint if the computer is retired.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-task"; Flags: runhidden; RunOnceId: "UbadsRemoveTask"

[Code]
const
  CodeMarker = '--ubads1.';

var
  HasCode: Boolean;
  WasRunning: Boolean;
  Outcome: String;
  FinalHeading: String;
  FinalText: String;
  EnrollExit: Integer;
  StepReached: String;

function GetCurrentProcessId: Cardinal; external 'GetCurrentProcessId@kernel32.dll stdcall';

function AgentHome: String;
begin
#ifdef TESTBUILD
  Result := ExpandConstant('{localappdata}\UBADS-TEST\Agent');
#else
  Result := ExpandConstant('{commonappdata}\UBADS\Agent');
#endif
end;

function AgentExe: String;
begin
  Result := ExpandConstant('{app}\{#MyAppExeName}');
end;

function BoolText(B: Boolean): String;
begin
  if B then Result := 'true' else Result := 'false';
end;

function JsonEscape(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
end;

{ Non-secret progress notes. Never contains the code, the credential or the setup file's path. }
procedure Note(const Step: String; Code: Integer);
var
  Dir: String;
begin
#ifdef TESTBUILD
  Dir := AgentHome + '\logs';
  ForceDirectories(Dir);
  SaveStringToFile(Dir + '\installer.log',
    GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':') + ' ' + Step + ' exit=' + IntToStr(Code) + #13#10, True);
#endif
end;

function RunAgent(const Params: String; var Code: Integer): Boolean;
begin
  Result := Exec(AgentExe, Params, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code);
  if not Result then
    Code := -1;
end;

function EnrollMessage(Code: Integer): String;
begin
  case Code of
    2:  Result := 'This installer does not carry a valid enrollment code. Download a fresh installer from the UBADS portal.';
    10: Result := 'The enrollment code in this installer is not valid. Download a fresh installer from the UBADS portal.';
    11: Result := 'The enrollment code has expired. Download a fresh installer from the UBADS portal.';
    12: Result := 'The enrollment code was already used. Download a fresh installer from the UBADS portal.';
    13: Result := 'An administrator revoked this authorization.';
    14: Result := 'This request is not approved for enrollment. Check its status in the UBADS portal.';
    15: Result := 'Too many failed attempts. Wait a few minutes, then run the installer again.';
    16: Result := 'This computer''s identity is already registered on the server. Ask an administrator for help.';
    20: Result := 'The UBADS server could not be reached. Check the internet connection and run the installer again.';
    21: Result := 'The server''s security certificate could not be verified, so enrollment was stopped.';
    22: Result := 'The UBADS server had a problem. Try again later.';
    23: Result := 'The server''s answer was not in the expected format. Download a fresh installer from the UBADS portal.';
    24: Result := 'The server address in this installer is not acceptable (or differs from the server this computer already uses).';
    30: Result := 'This computer could not store the agent''s data securely (Windows data protection or the data folder).';
    31: Result := 'The server enrolled this computer but the credential could not be stored. Ask an administrator to revoke the request, then request again.';
  else
    Result := 'Enrollment did not complete.';
  end;
end;

function ReadApprovedScope: String;
var
  Lines: TArrayOfString;
  I: Integer;
  Prefix: String;
  Value: String;
  Quote: Integer;
begin
  Result := '';
  Prefix := '  "categories": "';
#ifdef TESTBUILD
  if LoadStringsFromFile(AgentHome + '\agent.env', Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
      if Pos('CATEGORIES=', Lines[I]) = 1 then
        Result := Copy(Lines[I], Length('CATEGORIES=') + 1, MaxInt);
#else
  if LoadStringsFromFile(AgentHome + '\config\agent.json', Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
      if Pos(Prefix, Lines[I]) = 1 then
      begin
        Value := Copy(Lines[I], Length(Prefix) + 1, MaxInt);
        Quote := Pos('"', Value);
        if Quote > 0 then
          Result := Copy(Value, 1, Quote - 1);
      end;
#endif
end;

procedure WriteResult;
var
  Json, SelfName: String;
begin
#ifdef TESTBUILD
  SelfName := ExtractFileExt(ParamStr(0));
  Json := '{' + #13#10 +
    '  "outcome": "' + Outcome + '",' + #13#10 +
    '  "step_reached": "' + StepReached + '",' + #13#10 +
    '  "enroll_exit": ' + IntToStr(EnrollExit) + ',' + #13#10 +
    '  "had_code_in_name": ' + BoolText(HasCode) + ',' + #13#10 +
    '  "setup_process_extension": "' + SelfName + '",' + #13#10 +
    '  "is_admin": ' + BoolText(IsAdmin) + ',' + #13#10 +
    '  "elevated_build": ' + BoolText({#ElevatedBuildLiteral}) + #13#10 +
    '}' + #13#10;
  ForceDirectories(AgentHome + '\logs');
  SaveStringToFile(AgentHome + '\logs\installer-result.json', Json, False);
#endif
end;

procedure Finish(const AOutcome, Heading, Text: String);
begin
  Outcome := AOutcome;
  FinalHeading := Heading;
  FinalText := Text;
end;

{ Steps 4-9 of the documented installation sequence. }
procedure DoEnrollment;
var
  Rc: Integer;
  Flags, Scope: String;
begin
  Flags := '';
#ifdef TESTBUILD
  Flags := ' --allow-local';   { the test backend is on 127.0.0.1 }
#endif

  StepReached := 'enroll';
  WizardForm.StatusLabel.Caption := 'Enrolling this computer with your administrator-approved request...';
  if not RunAgent('--enroll-from-process ' + IntToStr(GetCurrentProcessId) + Flags, Rc) then
  begin
    EnrollExit := -1;
    Note('enroll(start-failed)', -1);
    Finish('failed', 'UBADS setup did not complete', 'The agent program could not be started, so this computer was not enrolled. Nothing is scheduled or running.');
    Exit;
  end;
  EnrollExit := Rc;
  Note('enroll', Rc);

  if Rc = 3 then
  begin
    Finish('already_enrolled', 'UBADS is already set up on this computer',
      'This computer is already enrolled, so its existing credentials were kept and nothing was changed except the program files. The enrollment code in this installer was not used.');
    Exit;
  end;
  if Rc <> 0 then
  begin
    Finish('failed', 'UBADS setup did not complete',
      EnrollMessage(Rc) + #13#10#13#10 + '(Error code ' + IntToStr(Rc) + '.) Nothing was scheduled and the agent is not running.');
    Exit;
  end;

  StepReached := 'verify-credential';
  WizardForm.StatusLabel.Caption := 'Checking the stored credential with the server...';
  RunAgent('--verify-enrollment', Rc);
  Note('verify-credential', Rc);
  if Rc <> 0 then
  begin
    Finish('failed', 'UBADS setup did not complete',
      'Enrollment finished, but the stored credential could not be confirmed with the server (code ' + IntToStr(Rc) + '). The agent was not scheduled or started.');
    Exit;
  end;

  StepReached := 'install-task';
  WizardForm.StatusLabel.Caption := 'Scheduling the agent to start automatically...';
  RunAgent('--install-task', Rc);
  Note('install-task', Rc);
  if Rc <> 0 then
  begin
    Finish('failed', 'UBADS setup did not complete',
      'This computer is enrolled, but the startup task could not be created (code ' + IntToStr(Rc) + '), so the agent was not started.');
    Exit;
  end;

  StepReached := 'start';
  WizardForm.StatusLabel.Caption := 'Starting the agent...';
  RunAgent('--start', Rc);
  Note('start', Rc);
  if Rc <> 0 then
  begin
    Finish('failed', 'UBADS setup did not complete',
      'This computer is enrolled and scheduled, but the agent did not start (code ' + IntToStr(Rc) + ').');
    Exit;
  end;

  StepReached := 'verify-running';
  WizardForm.StatusLabel.Caption := 'Confirming the agent is running and connected...';
  RunAgent('--verify-enrollment --require-running', Rc);
  Note('verify-running', Rc);
  if Rc <> 0 then
  begin
    Finish('failed', 'UBADS setup did not complete',
      'The agent was started, but its connection to the server could not be confirmed (code ' + IntToStr(Rc) + ').');
    Exit;
  end;

  StepReached := 'done';
  Scope := ReadApprovedScope;
  if Scope = '' then Scope := '(see your UBADS portal request)';
  Finish('success', 'UBADS agent is installed and connected',
    'This computer is enrolled and the background agent is running and connected to the UBADS server.' + #13#10#13#10 +
    'Approved monitoring scope: ' + Scope + #13#10#13#10 +
    'The installer did not enable any Windows audit policy; an administrator must enable the matching policies for events to be collected. ' +
    'To remove the agent, use Windows Settings > Apps > Installed apps > UBADS Windows Endpoint Agent > Uninstall.');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Rc: Integer;
begin
  Result := '';
#ifndef TESTBUILD
  { Do not replace an older install or its state until an explicit, reviewed migration exists. }
  if FileExists(AgentExe) then
  begin
    Result := 'An existing UBADS Agent installation was found. The upgrade was stopped without changing it; an administrator must complete the supported state migration first.';
    Exit;
  end;
  if FileExists(ExpandConstant('{localappdata}\UBADS\Agent\.state\credentials.json')) or
     FileExists(ExpandConstant('{localappdata}\UBADS\Agent\.state\identity.json')) or
     FileExists(ExpandConstant('{localappdata}\UBADS\Agent\.state\checkpoint.json')) or
     FileExists(ExpandConstant('{localappdata}\UBADS\Agent\.state\runtime_state.json')) or
     FileExists(ExpandConstant('{localappdata}\UBADS\Agent\.state\pending_events.jsonl')) or
     FileExists(ExpandConstant('{localappdata}\UBADS\Agent\agent.env')) then
  begin
    Result := 'This endpoint has legacy per-user agent state. The upgrade was stopped without changing it; an administrator must complete the supported state migration first.';
    Exit;
  end;
#endif
  { An upgrade: remember whether the agent was running, then stop it cleanly so its files can be replaced. }
#ifdef TESTBUILD
  WasRunning := FileExists(AgentHome + '\.state\agent.pid');
#else
  WasRunning := FileExists(AgentHome + '\state\agent.pid');
#endif
  if FileExists(AgentExe) then
    Exec(AgentExe, '--stop', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Rc);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Rc: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;

  { Step 2 - authorization input: only a yes/no test; the value is not kept. }
  HasCode := Pos(CodeMarker, ParamStr(0)) > 0;

#ifdef TESTBUILD
  { Isolation: redirect this install's agent state folder and task name (read by the agent at start-up). }
  SaveStringToFile(ExpandConstant('{app}\ubads-agent.profile'),
    '{"mode": "test", "state_dir": "' + JsonEscape(AgentHome + '\.state') + '", "task_name": "UBADS Agent TEST"}', False);
#endif

  if not HasCode then
  begin
    StepReached := 'no-code';
    Finish('files_only', 'UBADS agent files installed (not enrolled)',
      'The program files were installed, but this installer''s file name carries no enrollment code, so this computer was NOT enrolled and nothing is scheduled or collected.' + #13#10#13#10 +
      'To enroll: sign in to the UBADS portal, open your approved request and download the installer from there.');
  end
  else
    DoEnrollment;

  { Do not leave an upgraded, already-working agent stopped. }
  if ((Outcome = 'files_only') or (Outcome = 'already_enrolled')) and WasRunning then
  begin
    RunAgent('--start', Rc);
    Note('restart-previous-agent', Rc);
  end;
  WriteResult;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and (FinalHeading <> '') then
  begin
    WizardForm.FinishedHeadingLabel.Caption := FinalHeading;
    WizardForm.FinishedLabel.Caption := FinalText;
  end;
end;
