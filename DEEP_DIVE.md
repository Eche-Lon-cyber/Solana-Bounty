Fortifying Solana: A Deep Dive into Common Anchor Vulnerabilities

Introduction
Solana's account model is unique. Unlike EVM, where state and logic are coupled in a contract, Solana separates them: Programs are stateless, and Accounts are passed into them. This creates a "trust no one" environment where every single input account must be rigorously validated.
This deep dive explores five critical security patterns that every Solana developer must master to prevent exploits.

1. Missing Signer Checks
The Vulnerability:
The most basic Solana security rule is verifying who is calling the instruction. If a sensitive action like withdrawing funds or changing an admin takes an account as a parameter but doesn't check if that account signed the transaction, anyone can impersonate that account.
The Fix:
In Anchor, use the Signer<'info> type. If you use AccountInfo<'info> without a #[account(signer)] constraint, the program blindly accepts the public key without proving ownership.

2. Missing Owner & Type Checks
The Vulnerability:
On Solana, bytes are just bytes. A malicious user can create a generic account, fill it with data that looks like your UserStats struct, and pass it to your program. If you don't check that the account is actually owned by your program, you might process fake data as if it were valid state.
The Fix:
Anchor's Account<'info, MyType> wrapper automatically checks that:
The account is owned by the executing program (via program_id).
The account discriminator matches the expected type.
Using raw AccountInfo bypasses these safety checks.

3. Arbitrary CPI (Cross-Program Invocation)
The Vulnerability:
When your program interacts with another program, you must pass the target program's address as an account. If you don't verify this address, an attacker can pass a malicious program that mimics the SPL Token interface but steals funds or fakes a transfer success.
The Fix:
Always verify the program_id of the program you are calling. In Anchor, using Program<'info, Token> ensures the passed account is strictly the official SPL Token Program.

4. Missing Relationship Constraints
The Vulnerability:
Even if all accounts are valid and owned by the right programs, they might not belong to each other. For example, allowing Alice to withdraw tokens from a vault that belongs to Bob.
The Fix:
Use the has_one constraint. #[account(has_one = authority)] ensures that the authority field stored inside the data account matches the authority key passed in the transaction.

5. Re-Initialization Attacks
The Vulnerability:
If an instruction initializes an account (sets its state) but doesn't check if it has already been initialized, an attacker can call it again to reset the state—wiping out user balances or resetting admin controls.
The Fix:
Anchor's init constraint handles this safely by checking the discriminator. If you are doing manual initialization, you must verify the account data is empty or use a boolean flag like is_initialized to prevent overwrites.


1. Missing Signer Check
src/instructions/ex01_missing_signer.rs

use anchor_lang::prelude::*;

pub fn exec_vulnerable(ctx: Context<VulnerableContext>) -> Result<()> {
    // VULNERABILITY: This function updates the admin, but does not check 
    // if the 'current_admin' actually signed the transaction.
    // ANYONE can call this and change the admin to themselves.
    let data = &mut ctx.accounts.data_account;
    data.admin = ctx.accounts.new_admin.key();
    Ok(())
}

pub fn exec_secure(ctx: Context<SecureContext>) -> Result<()> {
    // FIX: The context struct defines 'current_admin' as a Signer.
    // Anchor will reject the transaction if the signature is missing.
    let data = &mut ctx.accounts.data_account;
    data.admin = ctx.accounts.new_admin.key();
    Ok(())
}

#[derive(Accounts)]
pub struct VulnerableContext<'info> {
    #[account(mut)]
    pub data_account: Account<'info, DataAccount>,
    /// CHECK: This is unsafe. It should be a Signer.
    pub current_admin: AccountInfo<'info>, 
    pub new_admin: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct SecureContext<'info> {
    #[account(
        mut, 
        has_one = current_admin // Ensures data_account.admin == current_admin.key()
    )]
    pub data_account: Account<'info, DataAccount>,
    pub current_admin: Signer<'info>, // <--- ENFORCES SIGNATURE
    pub new_admin: SystemAccount<'info>,
}

#[account]
pub struct DataAccount {
    pub admin: Pubkey,
}


2. Missing Owner Check (Account Injection)
src/instructions/ex02_missing_owner.rs

use anchor_lang::prelude::*;

pub fn exec_vulnerable(ctx: Context<VulnerableContext>) -> Result<()> {
    // VULNERABILITY: We are using AccountInfo without checking the owner.
    // An attacker can create a fake account with the same data layout 
    // and pass it in to trick the program.
    let account_data = ctx.accounts.user_account.try_borrow_data()?;
    // ... logic reading data ...
    Ok(())
}

pub fn exec_secure(ctx: Context<SecureContext>) -> Result<()> {
    // FIX: Using Account<'info, UserProfile> automatically checks:
    // 1. owner == program_id
    // 2. account discriminator matches UserProfile type
    let user_profile = &ctx.accounts.user_account;
    msg!("User score: {}", user_profile.score);
    Ok(())
}

#[derive(Accounts)]
pub struct VulnerableContext<'info> {
    /// CHECK: Unsafe! Could be any account (owned by any program).
    pub user_account: AccountInfo<'info>, 
}

#[derive(Accounts)]
pub struct SecureContext<'info> {
    // <--- ENFORCES OWNER & TYPE
    pub user_account: Account<'info, UserProfile>, 
}

#[account]
pub struct UserProfile {
    pub score: u64,
}


3. Arbitrary CPI (Fake Token Attack)
src/instructions/ex03_arbitrary_cpi.rs

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

pub fn exec_vulnerable(ctx: Context<VulnerableContext>, amount: u64) -> Result<()> {
    // VULNERABILITY: The user passes 'token_program' as an AccountInfo.
    // We invoke it blindly. The user could pass a malicious program ID 
    // that accepts this instruction but does something else (or nothing).
    let cpi_accounts = token::Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    // DANGEROUS: Using a generic AccountInfo for the program
    let cpi_program = ctx.accounts.token_program.to_account_info(); 
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}

pub fn exec_secure(ctx: Context<SecureContext>, amount: u64) -> Result<()> {
    // FIX: The context requires 'token_program' to be the actual SPL Token Program.
    let cpi_accounts = token::Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    // SAFE: Anchor validates the program ID matches SPL Token
    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct VulnerableContext<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    /// CHECK: Unsafe. Could be a malicious program.
    pub token_program: AccountInfo<'info>, 
}

#[derive(Accounts)]
pub struct SecureContext<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    // <--- ENFORCES PROGRAM ID
    pub token_program: Program<'info, Token>, 
}


4. Missing Relationship Constraint
src/instructions/ex04_missing_constraint.rs

use anchor_lang::prelude::*;
use anchor_spl::token::{TokenAccount};

pub fn exec_vulnerable(ctx: Context<VulnerableContext>) -> Result<()> {
    // VULNERABILITY: The 'vault' account stores an 'authority' field.
    // However, we never check if the 'signer' passed in is actually 
    // that authority. A thief can pass their own signer key and 
    // YOUR vault to withdraw funds.
    msg!("Withdrawing from vault...");
    Ok(())
}

pub fn exec_secure(ctx: Context<SecureContext>) -> Result<()> {
    // FIX: The 'has_one' constraint ensures that:
    // ctx.accounts.vault.authority == ctx.accounts.authority.key()
    msg!("Securely withdrawing from vault...");
    Ok(())
}

#[derive(Accounts)]
pub struct VulnerableContext<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>, // No check connecting this signer to the vault!
}

#[derive(Accounts)]
pub struct SecureContext<'info> {
    #[account(
        mut, 
        has_one = authority // <--- ENFORCES RELATIONSHIP
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub token_account: Pubkey,
}


5. Logic/State: Re-initialization
src/instructions/ex05_reinitialization.rs

use anchor_lang::prelude::*;

pub fn exec_vulnerable(ctx: Context<VulnerableContext>) -> Result<()> {
    // VULNERABILITY: This instruction manually sets data.
    // It does not check if the account was already initialized.
    // If called twice, it overwrites the 'owner' and resets 'points'.
    let user_data = &mut ctx.accounts.user_data;
    user_data.owner = ctx.accounts.authority.key();
    user_data.points = 100; 
    Ok(())
}

pub fn exec_secure(ctx: Context<SecureContext>) -> Result<()> {
    // FIX: Anchor's 'init' constraint automatically writes a discriminator.
    // If you try to 'init' an account that already has a discriminator,
    // the transaction fails.
    let user_data = &mut ctx.accounts.user_data;
    user_data.owner = ctx.accounts.authority.key();
    user_data.points = 100;
    Ok(())
}

#[derive(Accounts)]
pub struct VulnerableContext<'info> {
    // Standard mutable account, no initialization check
    #[account(mut)] 
    pub user_data: Account<'info, UserData>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SecureContext<'info> {
    #[account(
        init, // <--- ENFORCES INITIALIZATION SAFETY
        payer = authority,
        space = 8 + 32 + 8,
        seeds = [b"user", authority.key().as_ref()],
        bump
    )]
    pub user_data: Account<'info, UserData>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct UserData {
    pub owner: Pubkey,
    pub points: u64,
}





