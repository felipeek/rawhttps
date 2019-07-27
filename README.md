# TODO

## critical
- [x] Log all keys and useful information when log level is DEBUG
- [x] Logging should be thread-safe
- [ ] Crypto functions should use logger
- [ ] Resolve leaks with crypto functions
- [ ] Implement ALERT protocol
	- [x] Fetch ALERT
	- [ ] Wait for client CLOSE_NOTIFY gracefully in server loop
	- [ ] Handle gracefully the received alert in record layer, instead of throwing generic -1 error
- [ ] Check FINISHED's `verify_data`
- [ ] Use scheduler instead of one thread per connection
- [ ] Stop running threads in rawhttps_server_destroy
- [ ] Check behaviour of TLS with HTTP keep-alive
- [ ] Support certificate chain (and also redesign certificate load to load only once)
- [ ] Implement at least one STREAM cipher and maybe one AEAD cipher

## far future
- [ ] Implement session-id
- [ ] Implement compression methods
- [ ] Implement extensions
- [ ] Support for DH ciphers
