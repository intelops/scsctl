install:
	pip uninstall -y scsctl
	python -m build
	pip install dist/scsctl-0.0.4-py3-none-any.whl
