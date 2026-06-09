.PHONY: test build package release

test:
	pytest -q

build:
	docker compose build

package:
	mkdir -p release/threat-intel-hub
	touch release/traffic-ioc.txt release/traffic-ioc.csv release/traffic-ioc.json
	cp -r app alembic configs scripts release/threat-intel-hub/
	cp Dockerfile docker-compose.yml pyproject.toml alembic.ini README.md .env.example release/threat-intel-hub/
	cd release && tar -czf threat-intel-hub.tar.gz threat-intel-hub
	cd release && python3 -m zipfile -c threat-intel-hub.zip threat-intel-hub

release: test build package
