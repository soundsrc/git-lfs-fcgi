# Git LFS Server

*Warning: Not production ready*

This is a lightweight implementation of a GIT LFS server using the v1 batch API.
Currently, it is designed to be run as a FastCGI binary which can run under most
common server setup. A standalone server mode is provided for testing purposes.

## Building from source

```
cd build
make
```

## Running

```
./bin/Release/git-lfs-server-fcgi --base-url=http://yourhost.com/ --object-dir=/path/to/objects --socket=/tmp/git-lfs.socket
```

### Apache

TODO

### Nginx

TODO

### OpenBSD httpd

TODO

## TODO

* Support authentication
* Support verification
