# Solana Security Starter Kit

**An educational repository demonstrating common Solana security vulnerabilities and their fixes using the Anchor framework.**

This repository serves as a practical guide for developers to understand the "What" went wrong and "How" it is solved in Solana account security. It contains 5 distinct architectural patterns, presenting both a **broken (vulnerable)** implementation and a **fixed (secure)** implementation side-by-side.

> **Note:** This project is a submission for the SuperteamNG Security Bounty.

## Repository Contents

This repository is divided into code examples and educational content.

### 1. The Deep Dive
For a detailed written explanation of the logic behind these vulnerabilities, please read the included guide:
**[DEEP_DIVE.md](./DEEP_DIVE.md)**

### 2. Security Patterns Covered
The code examples are located in `programs/security-patterns/src/instructions/`.

| Pattern | Vulnerability | Why it matters |
| :--- | :--- | :--- |
| **01. Missing Signer** | `ex01_missing_signer.rs` | Prevents unauthorized users from performing privileged actions (e.g., changing admins). |
| **02. Type Cosplay** | `ex02_missing_owner.rs` | Prevents malicious users from injecting fake data accounts owned by other programs. |
| **03. Arbitrary CPI** | `ex03_arbitrary_cpi.rs` | Ensures Cross-Program Invocations interact only with legitimate programs (e.g., real SPL Token). |
| **04. Missing Relationship** | `ex04_missing_constraint.rs` | Uses `has_one` to ensure data accounts belong to the specific signer trying to use them. |
| **05. Re-Initialization** | `ex05_reinitialization.rs` | Prevents attackers from resetting an already active account's state. |

---

## Quick Start

Follow these steps to explore the code and run the build.

### Pre-equisites
- Rust & Cargo
- Solana CLI
- Anchor AVM

### Installation

1. **Clone the repository:**
   ```bash
   git clone <YOUR_REPO_URL_HERE>
   cd <YOUR_REPO_NAME>
   
