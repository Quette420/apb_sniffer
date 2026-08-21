### Запуск

```powershell
go run . `
    -src-port 6969 `
    -dst-port {меняется, искать командой ниже или из wireshark} `
    -device "\Device\NPF_Loopback" `
    -bidirectional `
    -key "{меняется, брать из консоли world server}" `
    -log-level info
```              

```powershell
Get-NetUDPEndpoint |
    Where-Object {$_.OwningProcess -eq 25772} |
    ForEach-Object {
        $port = $_.LocalPort

        [PSCustomObject]@{
            PID       = $_.OwningProcess
            LocalPort = $port
            Connections = Get-NetTCPConnection -OwningProcess 25772 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LocalPort -eq $port -or $_.RemotePort -eq $port
                }
        }
    }
```       