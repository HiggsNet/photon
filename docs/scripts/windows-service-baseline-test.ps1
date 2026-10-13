param([Parameter(Mandatory=$true)][string]$Helper)
$ErrorActionPreference='Stop'
. $Helper
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
public sealed class PhotonBaselineEchoTest : IDisposable {
    Socket socket;
    Thread worker;
    volatile bool stopping;
    bool delayFirst;
    public PhotonBaselineEchoTest(bool delay) {
        delayFirst=delay;
        socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback,19096));
        worker=new Thread(Serve);worker.IsBackground=true;worker.Start();
    }
    void Serve() {
        byte[] packet=new byte[2048];long count=0;
        while(!stopping) {
            try {
                EndPoint peer=new IPEndPoint(IPAddress.Any,0);
                int n=socket.ReceiveFrom(packet,ref peer);count++;
                if(delayFirst && count==1)Thread.Sleep(1100);
                if(count%3==0)continue;
                socket.SendTo(packet,0,n,SocketFlags.None,peer);
                socket.SendTo(packet,0,n,SocketFlags.None,peer);
            } catch(SocketException){if(!stopping)throw;}
              catch(ObjectDisposedException){if(!stopping)throw;}
        }
    }
    public void Dispose(){stopping=true;socket.Close();if(!worker.Join(2000))throw new Exception("Test echo did not stop");}
}
'@
$echo = New-Object PhotonBaselineEchoTest($false)
try {
    $r=[PhotonBaseline]::Run($PID,'127.0.0.1','127.0.0.1',1,1200,8)
    if($r.Sent -eq 0 -or $r.Echoed -eq 0 -or $r.Expired -eq 0 -or $r.Duplicates -eq 0 -or $r.Corrupt -ne 0) {throw 'Controlled loss/duplicate test did not exercise counters'}
    if($r.Sent -ne $r.Echoed-$r.LateEchoed+$r.Expired) {throw 'Unique echo accounting is inconsistent'}
    if($r.Seconds -gt 3 -or $r.Samples.Count -lt 2 -or $r.GoodputMbps -le 0) {throw 'Deadline/sampling/throughput failed'}
    $idle=[PhotonBaseline]::Run($PID,'','',1,1200,8)
    if($idle.Sent -ne 0 -or $idle.Echoed -ne 0 -or $idle.Samples.Count -lt 2) {throw 'Idle control generated traffic'}
    Write-Host "baseline helper controlled test passed: sent=$($r.Sent) unique=$($r.Echoed) expired=$($r.Expired) duplicates=$($r.Duplicates) samples=$($r.Samples.Count)"
} finally { $echo.Dispose() }
$echo = New-Object PhotonBaselineEchoTest($true)
try {
    $r=[PhotonBaseline]::Run($PID,'127.0.0.1','127.0.0.1',2,1200,8)
    if($r.LateEchoed -eq 0 -or $r.Duplicates -eq 0 -or $r.Corrupt -ne 0 -or $r.Sent -ne $r.Echoed-$r.LateEchoed+$r.Expired) {throw 'Delayed unique/duplicate accounting failed'}
    if($r.DeadlineGoodputMbps -ge $r.GoodputMbps) {throw 'Late packets erased the deadline miss evidence'}
    Write-Host "baseline delayed echo test passed: late=$($r.LateEchoed) duplicates=$($r.Duplicates) deadline_miss=$($r.DeadlineMissPercent)%"
} finally { $echo.Dispose() }
