# Sequential processing
Measure-Command { 
    $port = '53','80','88','443' 
    $port | ForEach-Object { 
            Test-NetConnection -ComputerName 8.8.8.8 -Port $_
    }
} | Select-Object Minutes,Seconds


# Parallel processing
Measure-Command {
    $port = '53','80','88','443'
    $port | ForEach-Object -Parallel {
            Test-NetConnection -ComputerName 172.30.5.10 -Port $_ 
    }
} | Select-Object Minutes,Seconds