Sentry: Cross-Platform AI-Driven Security Auditor
Sentry is a high-performance, lightweight security agent written in C that monitors filesystem integrity and leverages Python-based AI to classify potential threats. It is designed to meet ISO 27001 (A.12.4.1) compliance standards by generating immutable audit logs of all system-critical file events.

Core Features
Dual-Platform Core: Native support for both Linux (POSIX) and Windows (Win32) with zero code changes required at the application layer.

Integrity Hashing: Implements a standalone SHA-256 engine to create cryptographic baselines of sensitive files without external dependencies.

AI Handshake: Uses a high-speed NDJSON Bridge to stream telemetry from the C sensor to a Python inference engine.

Heuristic Fallback: Features a logic engine that utilizes OpenAI for deep analysis while maintaining a local heuristic rule-engine for offline environments.

Compliance-Ready: Automatically generates monthly_audit.csv ledgers formatted for enterprise security audits and regulatory review.

Technical Architecture
Sentry follows a Sensor-Bridge-Brain architecture to ensure low-level efficiency and high-level intelligence:

The Sensor (C): A low-level background daemon that monitors directories using inotify/readdir (Linux) or FindFirstFile (Windows).

The Bridge (JSON): A platform-aware logging system that synchronizes data between /var/log (Linux) and .\logs (Windows).

The Brain (Python): A watcher script that processes findings, performs AI classification, and determines the final "Verdict" (Authorized vs. Malicious).
Build and Deployment
The project uses a unified Makefile for cross-compilation, allowing for transitions between academic lab environments and personal workstations.

Linux (Ubuntu/Debian)
Bash

make linux
./bin/bridge
Windows (Portable EXE)
Bash

make windows
.\bin\sentry_core.exe
Testing the Pipeline
To verify the C-to-AI handshake and witness the classification engine in action:

Start the Brain: python3 ai/inference.py

Start the Sensor: ./bin/bridge

Simulate Tampering: Modify or delete a file in the test_files directory.

Verify Verdict: View logs/monthly_audit.csv to confirm the generated security verdict.
Project Team and Roles
Mostafa Ali | Project Lead and Cybersecurity Specialist

Systems Architecture: Engineered the native Win32/POSIX file scanning logic and the custom standalone SHA-256 implementation.

Compliance Mapping: Mapped system detections to the ISO 27001:A.12.4.1 framework and ensured the tool generates logs compatible with GDPR and PIPEDA requirements.

Vulnerability Research: Identified critical system paths and sensitive files (e.g., /etc/passwd, registry keys) for inclusion in the default monitoring scope.

Mohamed Hendy| AI and Security Logic Lead

Inference Engine: Developed the Python-based watcher and the integration with OpenAI's API for intelligent event classification.

Heuristic Engine: Built the local fallback logic to ensure system functionality in air-gapped or offline environments.

Ledger System: Designed the automated CSV reporting module to translate raw JSON findings into human-readable audit ledgers.

Ali Muqedi | Quality Assurance and Systems Integration

Attack Simulation: Developed and executed red-team simulations to verify the accuracy of the "Malicious" vs. "Authorized" classification logic.

Cross-Platform Integration: Assisted in the testing and debugging of the NDJSON bridge across Linux and Windows environments.

Documentation: Managed the technical documentation and user guides for the final deployment package.