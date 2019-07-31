run: build
	@echo "Running hobig tests..."
	@$(MAKE) --no-print-directory -C ./hobig run
	@echo "Running asn1 tests..."
	@$(MAKE) --no-print-directory -C ./asn1 run
	@echo "Running pkcs1 tests..."
	@$(MAKE) --no-print-directory -C ./pkcs1 run
build:
	@$(MAKE) --no-print-directory -C ./hobig build
	@$(MAKE) --no-print-directory -C ./asn1 build
	@$(MAKE) --no-print-directory -C ./pkcs1 build