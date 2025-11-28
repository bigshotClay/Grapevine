# Grapevine - Development Guidelines

## Project Overview

Grapevine is a decentralized, peer-to-peer social media platform built on IPv8 overlay networking and blockchain technology. The platform operates on the principle: "Owned by nobody; for everyone."

## Development Workflow

### Session Rules

**IMPORTANT: Complete only ONE feature/issue per session.**

1. At the start of each session, check the "Current Progress" section below
2. Work on the next incomplete item only
3. When finished with the feature:
   - Ensure tests pass
   - Update the "Current Progress" section to mark the item complete
   - Stop and wait for the next session
4. Do NOT continue to the next feature in the same session

### Working on Epics

When working on an epic, **complete one child issue at a time** in the order specified:

1. Read the epic issue to understand the full scope
2. Work on child issues **sequentially** in the listed order
3. Complete each issue fully before moving to the next:
   - Implement the feature
   - Write tests
   - Verify build passes
4. After completing ALL child issues, create a single PR for the entire epic
5. Do NOT work on multiple issues in parallel within an epic

This ensures:
- Each feature builds on the previous one correctly
- Dependencies between issues are respected
- Code review is manageable with atomic, focused changes

## Current Progress

Track completed work here to avoid repeating effort across sessions.

### Epic 3: Invitation System (In Progress)
- [x] #26 - Implement genesis user bootstrap mechanism
  - Added `is_genesis` column to identity table
  - Added `GENESIS` block type to TrustChainManager
  - Created `GenesisManager` class with `GenesisStorage` interface
  - Created `InMemoryGenesisStorage` for testing
  - Added `GenesisInfo`, `GenesisResult`, `ValidationResult` data classes
- [ ] #22 - FR-4: Invite Generation - Generate invite tokens
- [ ] #23 - FR-5: Invite Acceptance - Redeem invites and counter-sign
- [ ] #24 - FR-6: Invite Chain Recording - Record invites in distributed chain
- [ ] #25 - FR-7: Invite Tracing - View complete invite chain to genesis

### Completed Epics
- [x] Epic 1: Project Foundation & Infrastructure (#11-#17)
- [x] Epic 2: Identity Management (#18-#23)

## Technology Stack

- **Language**: Kotlin 2.1+ targeting JVM 17+
- **P2P Networking**: kotlin-ipv8 library
- **Blockchain**: TrustChain (via IPv8 TrustChainCommunity)
- **UI Framework**: Compose for Desktop (Multiplatform)
- **Database**: SQLite via SQLDelight
- **Cryptography**: Libsodium (Ed25519 signatures, X25519 key exchange)
- **Build System**: Gradle with Kotlin DSL
- **Serialization**: Protocol Buffers for network messages, JSON for storage

## Code Review Requirements

All code must be reviewed before being merged into main. Follow these guidelines:

### Pull Request Process

1. **Create a feature branch** for all new work:
   ```bash
   git checkout -b feature/<descriptive-name>
   git checkout -b fix/<issue-description>
   git checkout -b epic/<epic-number>-<short-description>
   ```

2. **Make commits** with clear, descriptive messages

3. **Push your branch** and create a Pull Request:
   ```bash
   git push -u origin <branch-name>
   gh pr create --title "Description" --body "Details"
   ```

4. **Request review** - PRs require at least one approval before merging

5. **Address feedback** - Make requested changes and re-request review

6. **Merge to main** only after approval:
   ```bash
   gh pr merge --squash
   ```

### Review Checklist

Before approving a PR, reviewers should verify:

- [ ] Code follows Kotlin coding conventions
- [ ] All new code has accompanying tests
- [ ] Tests pass locally and in CI
- [ ] Code is properly documented where necessary
- [ ] No security vulnerabilities introduced
- [ ] Cryptographic operations use approved libraries (Libsodium)
- [ ] No hardcoded secrets or credentials
- [ ] Error handling is appropriate
- [ ] Code does not break existing functionality

## Testing Requirements

**All code must have accompanying tests before acceptance.**

### Test Coverage

- Unit tests are required for all new functionality
- Target >80% code coverage on core modules
- Integration tests for P2P networking components
- Tests must pass before PR can be merged

### Running Tests

```bash
./gradlew test
./gradlew check
```

### Test Guidelines

1. **Unit Tests**: Test individual functions and classes in isolation
2. **Integration Tests**: Test component interactions, especially for:
   - IPv8 overlay communication
   - TrustChain block creation and validation
   - Database operations
3. **Security Tests**: Verify cryptographic operations and signature validation

## Branch Strategy

- `main` - Production-ready code only. Protected branch.
- `feature/*` - New features under development
- `fix/*` - Bug fixes
- `epic/*` - Large feature sets corresponding to project epics

### Branch Rules

1. Never commit directly to `main`
2. All changes go through feature branches
3. Feature branches must be up-to-date with main before merging
4. Delete branches after merging

## Project Structure

```
grapevine/
├── core/       # Data models, cryptographic operations, chain logic
├── network/    # IPv8 integration, SocialOverlay, peer management
├── storage/    # Database access, content cache management
├── sync/       # Timeline synchronization, content distribution
├── ui/         # Compose Desktop user interface
└── app/        # Application entry point, dependency injection
```

## Security Considerations

- Private keys must be stored in OS-provided secure storage
- All blocks must be cryptographically signed and verified
- Content integrity verified against stored hashes
- No encryption on content chains (transparency is a core principle)
- Block signatures verified before processing

## Getting Help

- Check existing GitHub issues for known problems
- Reference the project epics (Issues #1-#10) for feature scope
- Follow the acceptance criteria defined in each epic
