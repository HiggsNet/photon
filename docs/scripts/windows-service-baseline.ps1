# Dot-sourced only by the isolated full-daemon SCM fixture. No production tuning.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
public sealed class PhotonBaselineSample {
    public double Seconds, CPUSeconds;
    public long PrivateBytes, WorkingSetBytes;
}
public sealed class PhotonBaselineResult {
    public string Family;
    public int PayloadBytes, Window, ReceiveBufferBytes, SendBufferBytes;
    public long Sent, Echoed, Expired, LateEchoed, Duplicates, Unmatched, Corrupt, SendBackpressure;
    public double Seconds, SendSeconds, GoodputMbps, DeadlineGoodputMbps, EchoLossPercent, DeadlineMissPercent, ServiceCPUCorePercent, GeneratorCPUCorePercent;
    public List<PhotonBaselineSample> Samples = new List<PhotonBaselineSample>();
}
public static class PhotonBaseline {
    static void Sample(Process service, DateTime started, Stopwatch watch, PhotonBaselineResult result) {
        service.Refresh();
        if (service.HasExited || service.StartTime != started) throw new Exception("Baseline service process changed");
        result.Samples.Add(new PhotonBaselineSample {Seconds=watch.Elapsed.TotalSeconds,CPUSeconds=service.TotalProcessorTime.TotalSeconds,PrivateBytes=service.PrivateMemorySize64,WorkingSetBytes=service.WorkingSet64});
    }
    public static PhotonBaselineResult Run(int pid, string local, string remote, int seconds, int size, int window) {
        if(seconds<1 || seconds>30 || size<24 || size>1200 || window<1 || window>256) throw new ArgumentException("Unbounded baseline parameters");
        using(Process service=Process.GetProcessById(pid))
        using(Process generator=Process.GetCurrentProcess()) {
            DateTime started=service.StartTime;
            PhotonBaselineResult r=new PhotonBaselineResult {Family=local==""?"idle":IPAddress.Parse(local).AddressFamily.ToString(),PayloadBytes=local==""?0:size,Window=local==""?0:window};
            Stopwatch clock=Stopwatch.StartNew();
            Sample(service,started,clock,r);
            double initialCPU=r.Samples[0].CPUSeconds, initialGenerator=generator.TotalProcessorTime.TotalSeconds, nextSample=.25;
            Socket socket=null;
            try {
                if(local!="") {
                    IPAddress address=IPAddress.Parse(local);
                    socket=new Socket(address.AddressFamily,SocketType.Dgram,ProtocolType.Udp);
                    socket.ReceiveBufferSize=4*1024*1024; socket.SendBufferSize=1024*1024;
                    socket.Bind(new IPEndPoint(address,0));socket.Connect(new IPEndPoint(IPAddress.Parse(remote),19096));socket.Blocking=false;
                    r.ReceiveBufferBytes=socket.ReceiveBufferSize;r.SendBufferBytes=socket.SendBufferSize;
                }
                byte[] send=new byte[size],receive=new byte[65536];
                byte[] nonce=Guid.NewGuid().ToByteArray();Array.Copy(nonce,send,16);
                for(int i=24;i<size;i++)send[i]=(byte)(i*31);
                long[] seen=new long[8192];
                Dictionary<long,double> pending=new Dictionary<long,double>();
                List<long> expired=new List<long>();double nextExpiry=0;
                while(clock.Elapsed.TotalSeconds<seconds || pending.Count>0) {
                    double now=clock.Elapsed.TotalSeconds;
                    if(now>=seconds+1.1)break;
                    if(now>=nextSample){Sample(service,started,clock,r);nextSample=now+.25;}
                    if(socket==null){Thread.Sleep(10);continue;}
                    if(now>=nextExpiry) {
                        expired.Clear();foreach(KeyValuePair<long,double> item in pending)if(now-item.Value>=1)expired.Add(item.Key);
                        foreach(long id in expired){pending.Remove(id);r.Expired++;}nextExpiry=now+.01;
                    }
                    // One bounded window; only an echoed or expired packet frees a slot.
                    while(pending.Count<window && clock.Elapsed.TotalSeconds<seconds) {
                        long id=r.Sent+1;Array.Copy(BitConverter.GetBytes(id),0,send,16,8);
                        try {if(socket.Send(send)!=size)throw new Exception("Partial UDP send");}
                        catch(SocketException e){if(e.SocketErrorCode!=SocketError.WouldBlock && e.SocketErrorCode!=SocketError.NoBufferSpaceAvailable)throw;r.SendBackpressure++;break;}
                        pending.Add(id,clock.Elapsed.TotalSeconds);r.Sent++;
                    }
                    if(!socket.Poll(1000,SelectMode.SelectRead))continue;
                    int count=socket.Receive(receive);bool valid=count==size;
                    if(valid)for(int i=0;i<16;i++)if(receive[i]!=nonce[i]){valid=false;break;}
                    if(valid)for(int i=24;i<size;i++)if(receive[i]!=(byte)(i*31)){valid=false;break;}
                    if(!valid){r.Corrupt++;continue;}
                    long reply=BitConverter.ToInt64(receive,16);
                    if(reply<1 || reply>r.Sent){r.Corrupt++;continue;}
                    if(reply<=r.Sent-seen.Length){r.Unmatched++;continue;}
                    int slot=(int)(reply%seen.Length);
                    if(seen[slot]==reply){r.Duplicates++;continue;}
                    seen[slot]=reply;r.Echoed++;
                    if(!pending.Remove(reply))r.LateEchoed++;
                }
                r.Expired+=pending.Count;
            } finally {if(socket!=null)socket.Dispose();}
            Sample(service,started,clock,r);r.Seconds=clock.Elapsed.TotalSeconds;r.SendSeconds=seconds;
            r.GoodputMbps=r.Echoed*size*8/r.Seconds/1000000;
            r.DeadlineGoodputMbps=(r.Echoed-r.LateEchoed)*size*8/r.Seconds/1000000;
            r.DeadlineMissPercent=r.Sent==0?0:100.0*r.Expired/r.Sent;
            r.EchoLossPercent=r.Sent==0?0:100.0*(r.Sent-r.Echoed)/r.Sent;
            r.ServiceCPUCorePercent=100*(r.Samples[r.Samples.Count-1].CPUSeconds-initialCPU)/r.Seconds;
            generator.Refresh();r.GeneratorCPUCorePercent=100*(generator.TotalProcessorTime.TotalSeconds-initialGenerator)/r.Seconds;
            return r;
        }
    }
}
'@
function Test-ServiceBaseline {
    $profileHelper = Join-Path $FixtureDirectory 'windows-service-profile.ps1'
    $profileEnabled = Test-Path $profileHelper
    if ($profileEnabled) { . $profileHelper }
    $profileCaptured = $false
    $owner = Read-OwnedProcess
    $before = Read-Status
    if (!$before.tunnel_ready -or !$before.ike.live -or !$before.ike.child_live) { throw 'Baseline requires live authenticated business tunnel' }
    $results = New-Object System.Collections.Generic.List[object]
    $rounds = 3
    $measureSeconds = 15
    $cpus = @(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors)
    $os = Get-CimInstance Win32_OperatingSystem
    $metadata = [ordered]@{
        SchemaVersion = 1
        CPUProfileEnabled = $profileEnabled
        StartedAtUTC = [DateTime]::UtcNow.ToString('o')
        ServicePID = $owner.Id
        ServiceStartedAtUTC = $owner.FixtureStartedAtUtc.ToString('o')
        ExecutableSHA256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        OS = $os.Caption
        OSVersion = $os.Version
        CPUs = $cpus
        TotalPhysicalMemoryBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        PayloadBytes = 1200
        Windows = @(8,64)
        SendSeconds = $measureSeconds
        WarmupSeconds = 2
        IdleSeconds = 5
        Window8Rounds = $rounds
        Window64Rounds = 1
        EchoDeadlineSeconds = 1
        SamplePeriodSeconds = 0.25
        CPUUnit = 'percent of one logical CPU; may exceed 100'
        ThroughputUnit = 'unique echoed application payload Mbps per direction; matched echo round trips, not saturation capacity'
        Results = $results
    }
    try {
        $results.Add([pscustomobject]@{ Phase='idle-before'; Round=0; Measurement=[PhotonBaseline]::Run($owner.Id,'','',5,1200,64) })
        foreach ($window in @(8,64)) {
        $windowRounds = $rounds
        if ($window -eq 64) { $windowRounds = 1 }
        for ($round=1; $round -le $windowRounds; $round++) {
            # Alternate family order to expose rather than hide order/thermal drift.
            $families = @(@('198.18.253.2','198.18.253.1'),@('fd00:7068:b4::2','fd00:7068:b4::1'))
            if ($round % 2 -eq 0) { [array]::Reverse($families) }
            foreach ($family in $families) {
                $warmup = [PhotonBaseline]::Run($owner.Id,$family[0],$family[1],2,1200,$window)
                if ($warmup.Corrupt -ne 0) { throw 'Baseline warmup returned corrupt payload' }
                $profilePrefix = $null
                if ($profileEnabled -and !$profileCaptured) { $profilePrefix = Start-FixtureCPUProfile $owner }
                try {
                    $measurement = [PhotonBaseline]::Run($owner.Id,$family[0],$family[1],$measureSeconds,1200,$window)
                } finally {
                    if ($profilePrefix) { Stop-FixtureCPUProfile $profilePrefix; $profileCaptured = $true }
                }
                $entry = [pscustomobject]@{ Phase='load'; Round=$round; Warmup=$warmup; Measurement=$measurement; RecoveryPassed=$false }
                $results.Add($entry)
                if ($measurement.Corrupt -ne 0) { throw 'Baseline returned corrupt payload' }
                # Zero deadline hits is a valid overload result, not permission
                # to hide it or abort before measuring recovery from the load.
                Check-Business "baseline-w$window-r$round-$($measurement.Family)-recovery"
                $current = Read-OwnedProcess
                if ($current.Id -ne $owner.Id -or $current.FixtureStartedAtUtc -ne $owner.FixtureStartedAtUtc) { throw 'Baseline SCM process changed' }
                $status = Read-Status
                if (!$status.tunnel_ready -or !$status.ike.live -or !$status.ike.child_live) { throw 'Baseline lost readiness' }
                $entry.RecoveryPassed = $true
                Write-Host "baseline window=$window round=$round family=$($measurement.Family) Mbps=$($measurement.GoodputMbps) deadline_Mbps=$($measurement.DeadlineGoodputMbps) echo_loss=$($measurement.EchoLossPercent)% service_core_cpu=$($measurement.ServiceCPUCorePercent)%"
            }
        }
        }
        $results.Add([pscustomobject]@{ Phase='idle-after'; Round=0; Measurement=[PhotonBaseline]::Run($owner.Id,'','',5,1200,64) })
        $metadata.CompletedAtUTC = [DateTime]::UtcNow.ToString('o')
        $metadata.Completed = $true
    } finally {
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $FixtureDirectory 'baseline.json')
    }
}
