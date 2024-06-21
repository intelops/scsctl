install:
	pip uninstall -y scsctl
	python -m build
	pip install dist/scsctl-0.0.6.20-py3-none-any.whl
	clear
	echo "scsctl has been installed"

push:
	docker build -t scsctl .
	docker tag scsctl:latest ghcr.io/jegathintelops/scsctl:rebuild_test
	docker push ghcr.io/jegathintelops/scsctl:rebuild_test
