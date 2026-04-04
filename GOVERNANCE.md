# Governance

Stealth is maintained by [@i2dor](https://github.com/i2dor).

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change before submitting a pull request.

### Guidelines

- Keep pull requests focused on a single change
- New detectors should follow the existing pattern in `api/detect_public.py`
- Each detector must return `(findings, warnings)` or `findings` depending on type
- Include a section in `README.md` documenting any new detector
- Frontend changes should not break the existing report layout

### Detector conventions

- Use `UPPER_SNAKE_CASE` for detector type names
- Severity must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- Every finding/warning must include: `type`, `severity`, `description`, `details`, `correction`
- Findings represent confirmed privacy leaks; warnings represent potential risks

## License

MIT — see [LICENSE](LICENSE).
