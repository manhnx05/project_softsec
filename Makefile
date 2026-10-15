.PHONY: install test streamlit analysis check

install:
	python -m pip install --upgrade pip
	python -m pip install -r requirement.txt

test:
	python -m pytest -q

streamlit:
	python -m streamlit run app.py --server.headless true

analysis:
	python -c "from src.c_analysis.runner import run_c_analysis; print(run_c_analysis().to_dict())"

check: test
