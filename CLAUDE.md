# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**nd-connection-platform** is a healthcare data connection platform designed to facilitate secure, compliant data integration and sharing. The project is currently in the initial setup phase with no source code yet committed.

### Key Characteristics
- Healthcare/HIPAA compliance in scope (see TEST_COVERAGE_ANALYSIS.md for context)
- Emphasis on data integrity, security, and auditability
- Multi-tenant or multi-provider connection capabilities (inferred from name)
- Testing-first mindset established upfront (see Recommended Testing Strategy below)

## Repository Status

Currently, the repository contains:
- `TEST_COVERAGE_ANALYSIS.md` — Baseline testing strategy and coverage recommendations
- `.git` — Standard git tracking

No source code has been added yet. When development begins, follow the architecture and testing guidance below.

## Recommended Architecture & Code Structure

When source code is added, organize the repository as follows. This structure scales from a monolith to microservices:

```
src/
├── domain/              # Core business logic (healthcare data models, connection rules)
│   ├── entities/        # Data entities (Connection, Provider, DataExchange)
│   ├── services/        # Domain services (ProviderRegistry, DataValidator)
│   └── errors/          # Domain-specific exceptions
├── application/         # Use cases and application orchestration
│   ├── commands/        # Command handlers (CreateConnection, ValidateData)
│   ├── queries/         # Query handlers (GetConnection, ListProviders)
│   └── dto/             # Data transfer objects (request/response shapes)
├── infrastructure/      # External integrations and data access
│   ├── database/        # Database adapters, migrations
│   ├── cache/           # Caching layer if applicable
│   ├── auth/            # Authentication/authorization handlers
│   └── external-api/    # Third-party API clients
├── api/                 # HTTP API layer (routes, middleware, error handling)
│   ├── routes/          # Endpoint definitions
│   ├── middleware/      # Common middleware (auth, logging, error handling)
│   └── health.ts        # Health check endpoint
├── config/              # Configuration management
│   └── environment/     # Environment-specific settings
└── utils/               # Shared utilities (validators, formatters, helpers)
```

**Key Principles:**
- Separate domain logic from infrastructure details — domain code should not depend on frameworks
- Use dependency injection to decouple components
- Keep API routes thin; move logic into services
- Database schemas and queries should be in `infrastructure/database/`, not scattered

## Development Commands

When the project is initialized with a language and framework, common commands will include:

```bash
# Install dependencies
npm install              # Node.js projects
poetry install          # Python projects

# Build and type check
npm run build           # Compile TypeScript if applicable
npm run type-check      # Run type checker

# Linting and formatting
npm run lint            # Run ESLint or equivalent
npm run format          # Auto-format code

# Testing
npm test                # Run all tests
npm test -- --watch     # Run tests in watch mode
npm test -- --coverage  # Run tests with coverage report
npm run test:unit       # Unit tests only
npm run test:integration # Integration tests only

# Local development
npm run dev             # Start dev server with hot-reload
npm run start           # Start production build

# Database (if applicable)
npm run db:migrate      # Apply pending migrations
npm run db:seed         # Seed with test data
```

Replace `npm` with your project's package manager (yarn, pnpm, uv, poetry, gradle, etc.).

## Testing Strategy

Per TEST_COVERAGE_ANALYSIS.md, establish testing in this priority order:

### 1. Unit Tests (Highest Priority)
- Cover domain services, business logic, and utility functions
- Mock external dependencies (database, APIs)
- Target: 80%+ coverage on core domain and application layers
- Example structure:
  ```
  tests/unit/
  ├── domain/services/
  ├── application/commands/
  └── utils/
  ```

### 2. Integration Tests
- Verify interactions between layers (API → Service → Database)
- Use in-memory or test database instances
- Test authentication/authorization end-to-end
- Example structure:
  ```
  tests/integration/
  ├── api/
  ├── database/
  └── workflows/
  ```

### 3. API / Contract Tests
- Validate request/response schemas for all endpoints
- Test error responses (400, 401, 403, 404, 500)
- Verify backwards compatibility on API changes

### 4. Edge Cases & Error Handling
- Null/undefined inputs, empty collections, boundary values
- Network failures, timeouts, retries
- Concurrent access and race conditions

### 5. CI/CD
- Configure pre-commit hooks for linting and type-checking
- Run full test suite on PR with coverage gates (minimum 70% suggested)
- Publish coverage reports in CI artifacts
- Include static analysis (SAST) for security-sensitive healthcare code

## Code Conventions

### Naming & Structure
- Use **domain-driven naming**: name classes and functions after domain concepts (Provider, DataExchange, ConnectionFactory) not technical roles
- Avoid generic names like `Manager`, `Handler`, `Utils` — be specific about responsibility
- Exports from a module should be explicit; avoid circular dependencies

### Error Handling
- Create domain-specific exception classes in `src/domain/errors/`
- Use structured error responses in API layer with consistent schema
- Log errors with context (userId, connectionId, etc.) for audit trails
- Never expose internal error details to clients (e.g., database stack traces)

### Async & Concurrency
- If using Node.js/JavaScript, prefer async/await over promises/callbacks
- Healthcare operations often involve multi-step processes (validation → storage → notification) — consider retry strategies and idempotency keys
- Document which operations are idempotent (safe to retry)

### Configuration & Secrets
- Use environment variables for secrets (API keys, database URLs)
- Load config at application startup; fail fast if required config is missing
- Never commit `.env` files or hardcode secrets
- Use a secrets manager in production (AWS Secrets Manager, HashiCorp Vault, etc.)

### Logging
- Log at appropriate levels: INFO for major operations, DEBUG for internals, WARN for degradation, ERROR for failures
- Include structured fields (userId, connectionId, action) for searchability
- Avoid logging sensitive data (passwords, tokens, PII)

### Database & Data Persistence
- Use migrations for schema changes (Flyway, Alembic, Liquibase, etc.)
- Write queries in a way that's testable (avoid raw SQL in business logic)
- Document non-obvious queries with intent comments
- Consider audit trails for healthcare data changes (who changed what, when)

## Code Review Checklist

When reviewing PRs:
1. **Architecture**: Does the change follow the recommended structure? Is logic in the right layer?
2. **Testing**: Are new features covered by tests? Do tests verify behavior, not implementation details?
3. **Error Handling**: Are errors logged with context? Do API responses have consistent error schemas?
4. **Configuration**: Are secrets externalized? Is the change environment-aware?
5. **Data Integrity**: For healthcare features, are audit trails in place? Is data validated before persistence?
6. **Performance**: Are N+1 queries avoided? Is caching used appropriately?
7. **Security**: No hardcoded credentials? Proper input validation? CORS/auth headers set correctly?

## Useful References

- **TEST_COVERAGE_ANALYSIS.md** — Baseline testing strategy and metrics
- Healthcare & compliance topics may require domain research — establish reference docs as the project grows
- When adding framework dependencies, maintain a DEPENDENCIES.md or similar with the reasoning for key choices

## Getting Started for New Contributors

1. Clone the repository and check out the branch for your task
2. Install dependencies using the command appropriate to the chosen language/framework
3. Read the TEST_COVERAGE_ANALYSIS.md and this CLAUDE.md for architecture context
4. Start by implementing domain entities and core business logic (not API routes first)
5. Write tests alongside code — aim for 80%+ coverage on domain logic
6. Run linting, type-check, and tests before opening a PR
7. Reference TEST_COVERAGE_ANALYSIS.md in your PR description if introducing a new testing layer

---

**Last Updated:** 2026-06-05
