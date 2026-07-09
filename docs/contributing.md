# Contributing

## Development Setup

```bash
git clone https://github.com/your-username/ai-packet-analyzer.git
cd ai-packet-analyzer
cp .env.example .env
make install
make docker-up   # Start PostgreSQL
make migrate
make dev         # Backend
make frontend    # Frontend (new terminal)
```

## Code Style

- **Python**: `black` formatting, `ruff` linting, `mypy` strict typing
- **TypeScript**: strict mode, no `any` unless unavoidable
- Run `make format` before committing

## Testing

```bash
make test        # Full suite with coverage
```

Write tests for every new module in `backend/tests/`. Keep coverage above 80%.

## Pull Request Guidelines

1. Fork and branch from `develop`
2. One logical change per PR
3. Include tests for new functionality
4. Run `make lint type-check test` before opening the PR
5. Update `docs/api.md` if you add or change endpoints

## Adding a New LLM Provider

1. Create `backend/app/llm/providers/your_provider.py`
2. Extend `BaseLLMProvider` and implement `complete()` + `health_check()`
3. Register in `explanation_engine.py → create_provider()`
4. Add the provider name to the `LLM_PROVIDER` type annotation in `config.py`
5. Add at least one test in `tests/test_ai/test_llm.py`

## Adding a New Anomaly Detector

1. Create `backend/app/ai/your_detector.py`
2. Implement `fit(X)`, `predict(X)` → `(labels, scores)`, `score_flows()`
3. Register in `AnomalyDetectorService.analyse()`
4. Add persistence (save/load) consistent with other detectors

## Commit Message Format

```
type(scope): short description

body (optional)
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
