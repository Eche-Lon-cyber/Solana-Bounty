# Solana Security Starter Kit

**An educational repository demonstrating common Solana security vulnerabilities and their fixes using the Anchor framework.**

This repository serves as a practical guide for developers to understand the "What" went wrong and "How" it is solved in Solana account security. It contains 5 distinct architectural patterns, presenting both a **broken (vulnerable)** implementation and a **fixed (secure)** implementation side-by-side.

> **Note:** This project is a submission for the SuperteamNG Security Bounty.

## Repository Contents

This repository is divided into code examples and educational content.

## This is a summary of the vulnerabilities and how they can be fixed.

1. Missing Signer Check
The Flaw: The program updates a critical account (like changing an admin) but only checks if the user passed the correct public key, not if they signed with it.

The Risk: An attacker can supply the current admin's public key (which is public knowledge) without knowing the private key, effectively impersonating them.

The Fix: Change the account type from AccountInfo (unsafe) to Signer (safe). This forces the transaction to fail if the corresponding private key didn't sign it.

2. Type Cosplay (Missing Owner Check)
The Flaw: The program blindly trusts the data inside an account without checking who owns it.

The Risk: An attacker creates a fake account with identical data structure (e.g., a "User Profile" with 1,000,000 points) but owns it themselves. They pass this fake account to your program, which reads the fake high score as valid.

The Fix: Use Account<'info, Type> instead of AccountInfo. Anchor automatically checks the Discriminator (a unique ID for that specific struct) and ensures the account is owned by your program.

3. Arbitrary CPI (Fake Program Attack)
The Flaw: The program calls another program (like a token transfer) but accepts the "Token Program" address as a generic account.

The Risk: An attacker passes a malicious program ID instead of the real SPL Token Program ID. The malicious program accepts the call and returns "Success" without actually moving any tokens, tricking your program into thinking payment was received.

The Fix: Use the Program<'info, Token> type. This forces Anchor to verify that the passed account is exactly the official SPL Token Program.

4. Missing Relationship Constraint
The Flaw: The program checks if an account is valid, but doesn't check if it belongs to the user calling the function.

The Risk: A "Vault" account is valid, and a "User" account is valid. But if you don't check the link between them, Bob could withdraw funds from Alice's vault by passing his own signer key and Alice's vault address.

The Fix: Use the has_one constraint (e.g., #[account(has_one = authority)]). This enforces that the authority saved inside the Vault matches the signer of the transaction.

5. Re-Initialization Attack
The Flaw: The program allows an instruction to set initial account data (like points = 0) without checking if the account has already been set up.

The Risk: An attacker calls the initialization instruction on an active account, resetting everyone's balances or overwriting the owner key to themselves.

The Fix: Use Anchor's init constraint. This sets a unique discriminator on the account. If anyone tries to init it again, the program detects the existing discriminator and blocks the transaction.


### 1. The Deep Dive
For a detailed written explanation of the logic behind these vulnerabilities, please read the included guide:
**[DEEP_DIVE.md](./DEEP_DIVE.md)**

### 2. Security Patterns Covered
The code examples are located in `programs/security-patterns/src/instructions/`.

| Pattern | Vulnerability | Why it matters |
| :--- | :--- | :--- |
| **01. Missing Signer** | `ex01_missing_signer.rs` | This prevents unauthorized users from performing privileged actions (e.g., changing admins). |
| **02. Type Cosplay** | `ex02_missing_owner.rs` | It prevents malicious users from injecting fake data accounts owned by other programs. |
| **03. Arbitrary CPI** | `ex03_arbitrary_cpi.rs` | This ensures Cross-Program Invocations interact only with legitimate programs (e.g., real SPL Token). |
| **04. Missing Relationship** | `ex04_missing_constraint.rs` | This utilizes `has_one` to ensure data accounts belong to the specific signer trying to use them. |
| **05. Re-Initialization** | `ex05_reinitialization.rs` | This prevents attackers from resetting an already active account's state. |

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
   
