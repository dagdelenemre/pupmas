# PUPMAS - Puppeteer Master

.PHONY: help install test clean run

help:
	@echo "PUPMAS - Advanced Cybersecurity Operations Framework"
	@echo ""
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean temporary files"
	@echo "  make run        - Run PUPMAS in TUI mode"
	@echo "  make run-cli    - Run PUPMAS in CLI mode"
	@echo ""

install:
	@echo "Installing PUPMAS dependencies..."
	pip3 install -r requirements.txt
	@echo "Installation complete!"

test:
	@echo "Running tests..."
	python3 -m pytest tests/ -v

clean:
	@echo "Cleaning temporary files..."
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/
	@echo "Clean complete!"

run:
	@echo "Starting PUPMAS TUI..."
	python3 pupmas.py --mode tui

run-cli:
	@echo "Starting PUPMAS CLI..."
	python3 pupmas.py --mode cli --help

dev:
	@echo "Starting PUPMAS in development mode..."
	python3 pupmas.py --mode tui --verbose 2
