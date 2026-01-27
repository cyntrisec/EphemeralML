# Minimal smoke-test enclave: proves that the EIF boots and PID1 stays alive.
FROM busybox:1.36

COPY init.sh /init
RUN chmod +x /init

# Nitro build-enclave uses CMD as argv.
CMD ["/init"]
