py:
	# Clear existing wheels to prevent conflicts on installation
	rm coeus-python/target/wheels/*.whl || true
	cd coeus-python; maturin build --release
	python3 -m pip install --force-reinstall coeus-python/target/wheels/*.whl
