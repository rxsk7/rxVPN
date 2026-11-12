# Живая проверка сборки rxvpn на настоящем конфиге — перед выпуском.
#   Запуск (из консоли с правами администратора), отдельным процессом — переживает обрыв связи:
#     Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','dev\live-run.ps1','-NewExe','target\release\rxvpn.exe'
# Что делает: бэкап exe защищённой копии, state.json и снимка охраны → останавливает rxvpn → подменяет exe →
# проходит сценарии (kill switch с гибридом, падение, перенятие, обычный выход, экран «интернет закрыт») →
# в finally возвращает всё как было и запускает прежний rxvpn. Отчёт и снимки экрана — в target\live-run\<время>.
param(
    [Parameter(Mandatory = $true)][string]$NewExe,
    [string]$Protected = "C:\Program Files\rxvpn",
    [string]$Task = "rxvpn\Autostart",
    [string]$Gateway = "192.168.0.1"
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$NewExe = (Resolve-Path $NewExe).Path
$helper = Join-Path $root "target\debug\examples\live_patch.exe"
$data = (Get-Content (Join-Path $Protected "data-path.txt") -Raw -Encoding UTF8).Trim()
$state = Join-Path $data "state.json"
$out = Join-Path $root ("target\live-run\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force $out | Out-Null
$log = Join-Path $out "log.txt"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing, UIAutomationClient, UIAutomationTypes

function Log([string]$m) { ("{0}  {1}" -f (Get-Date -Format "HH:mm:ss"), $m) | Add-Content -Path $log -Encoding UTF8 }
function Shot([string]$name) {
    try {
        $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
        $bmp.Save((Join-Path $out "$name.png")); $g.Dispose(); $bmp.Dispose()
    } catch { Log "снимок $name не вышел: $_" }
}
function Http([string]$url) {
    $c = & "$env:SystemRoot\System32\curl.exe" -s -o NUL -w "%{http_code}" --max-time 8 $url 2>$null
    if ($LASTEXITCODE -ne 0) { return "нет($LASTEXITCODE)" } else { return "$c" }
}
function Net([string]$title) {
    $lan = if (Test-Connection -ComputerName $Gateway -Count 1 -Quiet) { "ok" } else { "нет" }
    Log ("{0}: youtube={1} discord={2} instagram(VPN)={3} ya.ru={4} 1.1.1.1={5} роутер={6} блокировка={7}" -f $title,
        (Http "https://www.youtube.com/"), (Http "https://discord.com/"), (Http "https://www.instagram.com/"),
        (Http "https://ya.ru/"), (Http "http://1.1.1.1/"), $lan, (& $helper leftover))
}
function Procs { (Get-Process rxvpn, xray, winws -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name):$($_.Id)" }) -join " " }
function Start-Rx {
    schtasks /run /tn $Task | Out-Null
    Start-Sleep 3
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect("127.0.0.1", 47389)
        $s = $c.GetStream(); $r = New-Object System.IO.StreamReader $s
        $null = $r.ReadLine()
        $w = New-Object System.IO.StreamWriter $s; $w.WriteLine("show"); $w.Flush(); $c.Close()
    } catch { Log "окно показать не вышло: $_" }
}
function Stop-Rx { taskkill /F /T /IM rxvpn.exe 2>$null | Out-Null; Start-Sleep 3 }
function Wait-Connected([int]$sec) {
    for ($i = 0; $i -lt $sec; $i += 3) {
        $up = (Get-NetAdapter -Name rxvpn -ErrorAction SilentlyContinue).Status -eq "Up"
        if ($up -and (Get-Process xray -ErrorAction SilentlyContinue) -and ((Http "https://www.instagram.com/") -notlike "нет*")) {
            Log "подключено за ~$i с: $(Procs)"; return $true
        }
        Start-Sleep 3
    }
    Log "НЕ подключилось за $sec с: $(Procs)"; return $false
}
function Patch([string[]]$kv) { Log ("настройки " + ($kv -join " ") + ": " + (& $helper set $state $Protected @kv)) }
function Click-Button([string]$name) {
    try {
        $p = Get-Process rxvpn -ErrorAction Stop | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
        $rootEl = [System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle)
        $cond = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty), $name
        for ($i = 0; $i -lt 10; $i++) {
            $el = $rootEl.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
            if ($el) { break }
            Start-Sleep 1
        }
        if (-not $el) { Log "кнопка «$name» не найдена"; return $false }
        $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        Log "кнопка «$name» нажата"; return $true
    } catch { Log "кнопка «$name»: $_"; return $false }
}

$bak = Join-Path $out "backup"
New-Item -ItemType Directory -Force $bak | Out-Null
$exe = Join-Path $Protected "rxvpn.exe"
$guard = Join-Path $Protected "settings-guard.json"
try {
    Copy-Item $exe, $state, $guard -Destination $bak -ErrorAction Stop
    Log "бэкап в $bak; новая сборка $NewExe ($((Get-Item $NewExe).Length) байт)"
    Net "0. до начала (прежний rxvpn)"

    # ---- A. Запуск новой сборки на настоящем конфиге: kill switch вместе с гибридом ----
    Stop-Rx
    Copy-Item $NewExe $exe -Force -ErrorAction Stop
    Patch @("close_to_tray=false")   # чтобы закрытие окна было обычным выходом (шаг D)
    Start-Rx
    $ok = Wait-Connected 90
    Start-Sleep 5
    Net "A. новая сборка подключена (ждём: всё открывается, блокировка=True)"
    Shot "A-connected"
    netsh wfp show filters file="$out\wfp-A.xml" | Out-Null
    $x = Get-Content "$out\wfp-A.xml" -Raw
    Log ("A. фильтров «rxvpn kill switch» в wfp-A.xml: {0} (ждём 22: 16 постоянных, 2 туннель, 4 пакеты zapret)" -f ([regex]::Matches($x, "<name>rxvpn kill switch</name>")).Count)

    # ---- B. Убить rxvpn: интернет закрыт, локальная сеть работает ----
    Stop-Rx
    Net "B. rxvpn убит (ждём: всё «нет», роутер=ok, блокировка=True)"
    Shot "B-killed"

    # ---- C. Запустить снова: перенял и подключился ----
    Start-Rx
    $ok = Wait-Connected 90
    Net "C. запущен снова (ждём: всё открывается, блокировка=True)"
    Shot "C-adopted"

    # ---- D. Обычный выход: блокировка снялась ----
    $p = Get-Process rxvpn -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($p) { $null = $p.CloseMainWindow(); $gone = $p.WaitForExit(25000); Log "D. окно закрыто, процесс вышел: $gone" } else { Log "D. окна нет — обычный выход не проверен" }
    Start-Sleep 3
    Net "D. после обычного выхода (ждём: блокировка=False, ya.ru и 1.1.1.1 открываются напрямую)"
    Shot "D-exited"
    Stop-Rx

    # ---- E. Экран «интернет закрыт» и кнопка «Открыть интернет без VPN» ----
    Start-Rx
    $ok = Wait-Connected 90
    Stop-Rx
    Patch @("auto_connect=false")
    Start-Rx
    Start-Sleep 12
    Net "E1. перенял без автоподключения (ждём: всё «нет», блокировка=True)"
    Shot "E1-closed-screen"
    $clicked = Click-Button "Открыть интернет без VPN"
    Start-Sleep 5
    Net "E2. после кнопки (ждём: блокировка=False, ya.ru открывается)"
    Shot "E2-released"
} catch {
    Log "ОШИБКА СЦЕНАРИЯ: $_"
} finally {
    # ---- Откат: всё как было, прежний rxvpn запущен ----
    Stop-Rx
    Copy-Item (Join-Path $bak "rxvpn.exe") $exe -Force
    Copy-Item (Join-Path $bak "state.json") $state -Force
    Copy-Item (Join-Path $bak "settings-guard.json") $guard -Force
    Log ("откат: файлы возвращены; снять блокировку: " + (& $helper clear))
    Start-Rx
    $null = Wait-Connected 120
    Net "Z. прежний rxvpn возвращён"
    Shot "Z-restored"
    Log "конец"
}
