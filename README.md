# GPU Hash Auditor 🚀

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![CUDA](https://img.shields.io/badge/CUDA-76B900?style=for-the-badge&logo=nvidia&logoColor=white)

A high-performance, hardware-accelerated cybersecurity tool designed to audit MD5 and SHA-256 cryptographic hashes. 

This project utilizes a **Polyglot Architecture** to achieve maximum performance while maintaining a responsive user experience. By streaming massive datasets directly to the GPU in optimized chunks, it completely bypasses traditional system RAM bottlenecks and executes rule-based dictionary attacks using native NVIDIA CUDA hardware cores.

---

## 🏗️ Polyglot Architecture & Workflow
* **Frontend (Java Swing):** A lightweight, multithreaded control panel with real-time network telemetry, progress tracking, and dynamic UI-side hash translation.
* **Orchestrator (Python):** A memory-safe middleware socket server that handles network routing, parses multi-million-word dictionary files into manageable chunks, and streams raw, strictly-padded bytes to the hardware via the `ctypes` library.
* **Hardware Engine (C++ / CUDA):** A strictly memory-aligned kernel compiled to raw PTX for modern NVIDIA architectures (Ada Lovelace/Blackwell). It executes thousands of bitwise MD5/SHA-256 calculations simultaneously on the VRAM.

---

## ⚙️ Core Features
* **Multi-Algorithm Support:** Dynamically swap between MD5 (16-byte) and SHA-256 (32-byte) mathematical engines via the UI.
* **Byte-Level Memory Alignment:** Safely handles corrupted UTF-8 characters and variable-length strings found in real-world password leaks (e.g., `rockyou.txt`) without misaligning the C++ GPU memory grid.
* **Massive File Streaming:** Processes files infinitely larger than available system RAM by employing strict chunking and garbage collection algorithms in Python.
* **One-Click Automation:** Fully automated startup, network port binding, and shutdown sequencing via a custom Windows Batch orchestrator.

---

## 📂 Project Structure

```text
GPU-Hash-Auditor/
│
├── Dashboard.java      # Java Swing UI and socket client
├── server.py           # Python orchestrator and memory bridge
├── hasher.cu           # C++ CUDA kernel (MD5/SHA-256 logic)
├── RunAuditor.bat      # Windows batch execution script
├── README.md           # Project documentation
└── .gitignore          # Version control exclusion rules