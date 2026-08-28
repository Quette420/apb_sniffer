### Запуск

```powershell
go run ./cmd/sniffer `
    -src-port 6969 `
    -dst-port {меняется, искать командой ниже или из wireshark} `
    -device "\Device\NPF_Loopback" `
    -bidirectional `
    -key "{меняется, брать из консоли world server}" `
    -watch-csa `
    -log-level info
```              

`-watch-csa` разбирает каждый пакет, а не только первый пакет каждого
размера, и выводит только CSA-поля контроллера 338–345. Для поля 343
дополнительно показываются input mapping и целевой actor/channel; для 345 —
input mapping. Направления помечаются как `C2S` и `S2C`.

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
