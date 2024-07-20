
<h1 align="left">
  ZeroHVCI - Defeating HVCI without admin privileges or a kernel driver
</h1>

ZeroHVCI accomplishes arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers.
<img src="https://i.imgur.com/LE46Isc.png" alt="tab">
<h2>Features</h2>
<ul>
  <li>Full non-privileged kernel read/writes: Kernel read/writes are achieved by leveraging CVE-2024-26229 which requires no process elevation.</li>
  <li>Arbitrary Function Calling: Calls any arbitrary kernel functions with desired params fully from user land.</li>
</ul>

<h2>Getting Started</h2>
<p>To get started with ZeroHVCI, you can clone this repository and build the project.</p>
<h2>Usage</h2>

```C++
//
// Read kernel memory example:
//
ReadKernelMemory(source_address, buffer_address, size);
```

```C++
//
// Write kernel memory example:
//
WriteKernelMemory(source_address, buffer_address, size);
```

```C++
//
// Kernel function calling example via name:
//
KF::CallKernelFunctionViaName<kernel_param_type1, kernel_param_type2, kernel_param_type3>(
  "kernel_function_name",
  param1,
  param2,
  param3);
```

```C++
//
// ExAllocatePool example:
//
KF::CallKernelFunctionViaName<PVOID, POOL_TYPE, SIZE_T>("ExAllocatePool", PoolType, Size);
```

```C++
//
// memcpy example:
//
KF::CallKernelFunctionViaName<PVOID, PVOID, PVOID, SIZE_T>("memcpy", Dst, Src, Size);
```

```C++
//
// PsLookupProcessByProcessId example:
//
PEPROCESS Process;
KF::CallKernelFunctionViaName<NTSTATUS, HANDLE, PEPROCESS*>("PsLookupProcessByProcessId", ProcessHandle, &Process);
```

<h2>How it works</h2>
<p>Two main projects are responsible for making this possible</p>
<ul>
  <li> <b>CVE-2024-26229</b>- All credits to Eric Egsgard, this exploit allows us to gain kernel read/write by abusing a IOCTL with METHOD_NEITHER in csc.sys (a windows module, resources will be linked below if you want to read-up more.</li>
  <li> <b>KernelForge</b>- All credits to Dmytro Oleksiuk, his project allows us to gain HVCI-compliant kernel function calling by abusing the heirarchy of thread executions and construction rop chains without truly patching anything.</li>
</ul>


<h2>What is this for?</h2>
<p>This is a multi-purpose project which will help people in many sectors, this includes memory-hacking against anti-cheats like Riot Vanguard as we've seen with the HVCI enforcements, this can also be used as a toolkit against AVs/EDRs/XDRs due to the nature that it requires no escalation to
achieve arbitrary read/writes and calling kernel functions.</p>

<h2>Acknowledgements</h2>

Cr4sh for [KernelForge](https://github.com/Cr4sh/KernelForge)<br>
varwara for his [POC](https://github.com/varwara/CVE-2024-26229)<br>
Eric Egsgard for his [talk](https://www.youtube.com/watch?v=2eHsnZ4BeDI)
