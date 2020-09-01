# run the unittests with branch coverage
python -m poetry run python -m pytest --cov-branch --cov=./safe_eval --cov-report=xml tests/