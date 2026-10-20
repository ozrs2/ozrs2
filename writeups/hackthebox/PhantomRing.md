# PhantomRing — Reverse Engineering a Linux Remote Agent

**Omar Mohammed Jaradat** · Hack The Box Sherlock · Malware Analysis / DFIR

> **Evidence note:** The findings below are taken from the completed Sherlock investigation. The original ELF and its decompiler output were not available for fresh verification during publication. Commands are a repeatable analysis procedure, and explanations of code patterns are methodological examples, not claimed verbatim extracts of this binary. No malware file is hosted here.

## Case objective and thinking process

When examining an unfamiliar Linux executable, I do not begin by guessing the malware family. Instead, I divide the investigation into questions that can be answered by evidence: What is the sample? Where does it communicate? How is the main loop structured? What can a remote operator request? Which local artifacts does it access, and why might those matter to defenders?

The goal is to trace each observation **from bytes → references → functionality → security impact**, and to distinguish a confirmed behavior from a promising clue.

## 1. Preserve and triage the sample

Work inside an isolated malware-analysis VM. The filename in these examples is a placeholder and should be replaced with the executable from the authorized Sherlock package. Do not run it to answer questions that static analysis can resolve.

~~~bash
mkdir -p ~/cases/phantomring/{sample,evidence,notes}
cd ~/cases/phantomring
cp /path/to/extracted/ELF sample/agent
chmod -x sample/agent

sha256sum sample/agent | tee evidence/sha256.txt
file sample/agent | tee evidence/file.txt
readelf -hW sample/agent | tee evidence/elf_header.txt
readelf -SW sample/agent > evidence/sections.txt
readelf -Ws sample/agent > evidence/symbols.txt
strings -a -n 5 sample/agent > evidence/strings.txt
objdump -d -M intel sample/agent > evidence/disassembly.txt
~~~

**Reasoning:** The hash uniquely identifies the specimen, while ELF headers reveal architecture, linking, and structural details. Symbols and readable strings may give useful starting points, but cannot independently prove execution.

**Recovered SHA-256:** 2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5

## 2. Build a map in Ghidra

Import the executable into Ghidra and allow auto-analysis to finish. Before spending time in individual functions:

1. Check the entry point and follow control flow toward initialization and the main loop.
2. Review imported functions (if available) and the Defined Strings window.
3. Search for interesting constants, then follow **Show References To**.
4. Rename functions based on what their implementation demonstrably does.
5. Keep notes mapping every claim to a function address, referenced value, and supporting behavior.

**Important:** If the binary is stripped, absence of symbols is expected. References and call relationships remain more valuable than guessed labels. If symbols are present, verify rather than blindly trusting names.

## 3. Trace command-and-control initialization

### Hypothesis: there is a hardcoded network endpoint

Start with possible IP strings:

~~~bash
grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}' evidence/strings.txt
grep -Ei 'socket|connect|inet_|htons|sleep' evidence/symbols.txt
~~~

Finding a dotted IPv4 address only produces a **candidate IOC**. In Ghidra, inspect references to the candidate literal and check whether it feeds network address initialization. Follow the connection call and its arguments before asserting the address is a destination.

**Recovered address:** 192.168.56.1

This is a private IPv4 address, consistent with a training environment; it is not an Internet-routable adversary host.

### Find the port without being fooled by byte order

An integer port often never appears in readable strings. In the code building the socket-address structure, look for a constant stored into the port field, potentially through a byte-order conversion. Confirm both the value and its role.

**Recovered port:** 4445. **Endpoint:** 192.168.56.1:4445.

### Read the failure branch, not just the happy path

Next, inspect what happens after connection failure. Does the code exit, retry immediately, or call a delay primitive and loop? The duration must be interpreted in the called API's units; seconds and microseconds are easy to confuse.

**Recovered retry delay:** 120 seconds.

**Investigative lesson:** Correlating a hardcoded destination with its reconnect behavior describes the communication loop far better than recording an IP alone.

## 4. Reconstruct the command dispatcher

A remote agent becomes much more understandable once its command dispatch structure is known. Find the receive/read loop and trace the input buffer to comparisons, switch/jump-table handling, or command-specific functions.

My process for command counting:

1. Find the incoming-command parser.
2. Record each valid branch and the handler it reaches.
3. Follow aliases that converge on one handler.
4. Exclude the default or invalid-command path.
5. Count **distinct implemented operations**, not just strings.

One subtlety in PhantomRing: the command words **ss** and **netstat** map to the same handler (cmd_ss). Counting both as different capabilities gives an inflated result.

**Recovered count:** 11 distinct supported command handlers.

For a rigorous follow-up, record an evidence table with command token, dispatcher offset, handler address, argument parsing, observable action, and confidence. Without the original disassembly, I will not invent those missing offsets or eleven handler names.

## 5. Investigate io_uring without overstating evasion

The Sherlock highlights Linux **io_uring**, an asynchronous I/O interface. It can change which events appear on some syscall-focused monitoring paths, so it is relevant to defensive visibility.

Start with:

~~~bash
grep -ni 'io_uring' evidence/strings.txt
grep -i 'io_uring' evidence/symbols.txt
~~~

Then follow any setup, submission and completion routines in the disassembler. If the above searches are empty, this is **not** proof that io_uring is unused: direct system calls and inlined structures may leave no helpful symbols.

**Recovered interface:** io_uring.

The careful security claim is that reliance on a narrow class of syscall hooks may create monitoring gaps. This finding does **not** establish that all EDRs are bypassed, or that a specific product failed to detect the sample.

## 6. Explore host-discovery behavior

### Logged-in users

Search candidate session files in the extracted strings, then inspect how the associated function opens or parses them.

~~~bash
grep -niE 'utmp|wtmp|users|login' evidence/strings.txt
~~~

**Recovered file:** /var/run/utmp

This path is associated with logged-in session records. To establish enumeration, verify that the code processes the records rather than only checking file existence.

### SUID binaries

A suspicious process traversing directories and checking executable permission bits might be surveying possible privilege-escalation targets. The steps to validate this are: identify the traversal root, identify calls retrieving file metadata, and confirm a set-user-ID bit check.

**Recovered search directory:** /usr/bin

A search for SUID files is reconnaissance, **not evidence that privilege escalation succeeded**.

### BPF and tracing inspection

Two distinctive host artifacts emerged:

- **BPF descriptor:** anon_inode:bpf-map
- **Tracing configuration path:** /sys/kernel/debug/tracing/tracing_on

Search these values in Ghidra and follow references. For tracing, it is crucial to determine whether the code **reads**, **tests**, or **writes** the tracing configuration. Those operations support different conclusions. Likewise, finding a BPF-related descriptor is not equivalent to establishing that the agent loaded a BPF program.

## 7. Examine self-reference and cleanup

A remote operator may want an agent to clean itself up. The important distinction is between recognizing a cleanup instruction and proving the exact deletion mechanism.

**Recovered process executable reference:** /proc/self/exe  
**Recovered cleanup command:** sdestruct

Trace the sdestruct command branch to its implementation. Check how it references the current executable and what file or process operations follow. Avoid assuming a particular deletion API or execution sequence until verified in the sample.

From a DFIR perspective, collect hashes, file copies, process lineage, and filesystem telemetry early: self-removal behavior can make later reconstruction more difficult.

## 8. Analyst evidence matrix

| Question | Finding | Where to verify |
|---|---|---|
| Binary identity | SHA-256: 2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5 | Extracted file hash |
| C2 address | 192.168.56.1 | Address literal → socket initialization |
| C2 port | 4445 | Port field and byte-order conversion |
| Retry interval | 120 seconds | Failure branch → delay call |
| Agent capabilities | 11 commands | Unique valid dispatcher targets |
| Kernel interface | io_uring | Setup and related I/O paths |
| Session records | /var/run/utmp | File-reference cross-references |
| SUID scan root | /usr/bin | Traversal code and mode checks |
| BPF reference | anon_inode:bpf-map | Descriptor reference and use |
| Tracing reference | /sys/kernel/debug/tracing/tracing_on | Read/check/write path |
| Self executable | /proc/self/exe | Executable-path resolution |
| Cleanup command | sdestruct | Dispatcher and handler |

*The answers are retained from the challenge investigation. The final column is a verification plan, not a claim that new screenshots, addresses, or runtime telemetry were captured in this publishing session.*

## 9. Translating observations into defensive hypotheses

**Network:** Alert on unusual executable ancestry and repeated outbound connection attempts to unexpected destinations, then examine whether the retry cadence is regular.

**Reconnaissance:** Correlate suspicious processes reading session records with privileged-file enumeration, BPF inspection, or tracing-related activity. These individual acts can be legitimate; context matters.

**Visibility:** Assess whether your endpoint monitoring observes relevant io_uring operations in an **authorized lab**. Do not label an interface universally stealthy.

**Cleanup:** Investigate executable removal associated with remote-command processing; preserve the original specimen before artifacts disappear.

## 10. What would strengthen this into a fully reproducible report?

The next quality step is to add real Ghidra screenshots, function offsets, selected decompiler excerpts, the complete 11-command map, an evidence timeline, and sample-tested detection logic. Each addition should be tied to the exact hashed binary rather than reconstructed from memory.

## Conclusion

PhantomRing illustrates a central reversing lesson: **a string suggests a hypothesis; data flow and control flow make it evidence.** A useful malware writeup explains not only the final answers, but also what to investigate, how to avoid false conclusions, and how to translate findings into defensive action.

---

*Independent educational Sherlock writeup by Omar Mohammed Jaradat. The malicious executable is not distributed here.*
