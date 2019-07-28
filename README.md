# TODO

## critical
- [x] Log all keys and useful information when log level is DEBUG
- [x] Logging should be thread-safe
- [ ] Crypto functions should use logger
- [ ] Resolve leaks with crypto functions
- [x] Implement ALERT protocol (receiver)
- [x] Implement ALERT protocol (sender) and send meaningful messages
- [x] Check FINISHED's `verify_data`
- [ ] Use scheduler instead of one thread per connection
- [ ] Stop running threads in rawhttps_server_destroy
- [x] Check behaviour of TLS with HTTP keep-alive
- [-] Implement at least one STREAM cipher and maybe one AEAD cipher **(Hoshoyo refused to implement a STREAM cipher)**

## far future
- [ ] Modify code to support HTTP keep-alive
- [ ] Implement session-id
- [ ] Implement compression methods
- [ ] Implement extensions
- [ ] Support for DH ciphers
- [ ] Support certificate chain
