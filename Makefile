.PHONY: install test train run dashboard docker-up lint clean

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --tb=short --cov=ids --cov-report=term-missing

train:
	python scripts/train_model.py

run:
	sudo python -m ids.intrusion

dashboard:
	streamlit run dashboard/app.py

docker-up:
	docker compose up --build

lint:
	python -m py_compile ids/*.py scripts/*.py dashboard/*.py
	@echo "Syntax OK"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -f ids_alerts.log
