# 🎯 ДЕТАЛЬНАЯ MITRE ATT&CK МАТРИЦА: PHANTOM TAURUS

## 🔴 INITIAL ACCESS (ПЕРВОНАЧАЛЬНЫЙ ДОСТУП)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1190 | Exploit Public-Facing Application | Атака на IIS серверы | NET-STAR | Мониторинг w3wp.exe |

## 🟢 EXECUTION (ВЫПОЛНЕНИЕ)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1059 | Command-Line Interface | Использование cmd.exe | AssemblyExecuter | Audit command line |
| T1106 | Native API | .NET Assembly execution | Assembly.Load() | EDR monitoring |

## 🟡 PERSISTENCE (СОХРАНЕНИЕ)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1505 | Server Software Component | IIS backdoor | IIServerCore | File integrity monitoring |

## 🔵 DEFENSE EVASION (УКЛОНЕНИЕ ОТ ЗАЩИТЫ)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1070 | Indicator Removal | Timestomp | Timestomp | File metadata audit |
| T1562 | Impair Defenses | AMSI/ETW Bypass | Custom .NET | AMSI logging |

## 🟣 DISCOVERY (РАЗВЕДКА)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1083 | File and Directory Discovery | Reconnaissance | Yasso | Process monitoring |

## 🟠 CREDENTIAL ACCESS (ДОСТУП К УЧЕТНЫМ ДАННЫМ)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1003 | OS Credential Dumping | LSASS dumping | Mimikatz | LSASS protection |

## 🔶 COMMAND AND CONTROL (УПРАВЛЕНИЕ)
| Tactic | Technique | Description | Tools | Detection |
|--------|-----------|-------------|-------|-----------|
| T1071 | Application Layer Protocol | HTTPS C2 | Custom | SSL inspection |
| T1090 | Proxy | Traffic redirect | Htran | Network anomalies |

## 📊 MATRIX SUMMARY
```mermaid
graph TD
    A[Initial Access] --> B[Execution]
    B --> C[Persistence]
    C --> D[Defense Evasion]
    D --> E[Discovery]
    E --> F[Credential Access]
    F --> G[Command & Control]
