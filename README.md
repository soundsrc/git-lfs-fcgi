# Git LFS Server

*Warning: Not production ready*

This is an implementation of a FastCGI GIT LFS server using the v1 batch API.

This server is designed to be used when you already are serving Git over HTTP with an
existing webserver and you want to add LFS support. It is a FastCGI binary that should
interface with most webservers after a bit of configuration.

# TODO

* Support permissions on Git LFS locks
* Test suite

## Building from source

CMake is required for the build.

```
cmake
make
```

For the first time, you must create the "git-lfs" user and group.

```
sudo groupadd git-lfs
sudo useradd git-lfs
```

Also create the /var/lib/git-lfs-server/run directory and make them accessible by the git-lfs user.

```
sudo install -d -m 0755 -o git-lfs -g git-lfs /var/lib/git-lfs-server
sudo install -d -m 0755 -o git-lfs -g git-lfs /var/lib/git-lfs-server/run
```


## Configuration

The GIT-LFS server requires a configuration file to operate.

For example, if you run a GIT repository at https://git-server.com/foo/bar.git and you want to serve
a LFS server on https://git-server.com/foo/bar.git/info/lfs and you want to store your LFS objects
in the directory /var/lib/git-lfs-server/foo/bar.git/lfs.

Create a file at /etc/git-lfs-server/git-lfs-server.conf and the configuration might look like this:


```
base_url "https://git-server.com"
chroot_path "/var/lib/git-lfs-server"
repo "Foobar Repository"
{
	uri "/foo/bar.git/info/lfs"
	root "/var/lib/git-lfs-server/foo/bar.git/lfs"
}
```

See examples in the conf/ directory for more ways to configure your repositories.

Man pages located in man/ fully document the configuration files.

See:

[git-lfs-server.conf (5)](man/git-lfs-server.conf.txt)

[git-lfs-server (8)](man/git-lfs-server.txt)

## FastCGI configuration

Using the example of https://git-server.com/foo/bar.git/info/lfs,
the webserver should now be configured to listen on the URI /foo/bar.git/info/lfs
and have the request passed via FastCGI to the socket listening on

/var/lib/git-lfs-server/run/git-lfs-server.sock

The webserver should also ideally be secured with HTTPS and authentication.
Instructions for setting this up will vary depending on the webserver.

### NGINX

In your server configuration, you might add a location block that looks like this:

```
location /foo/bar.git/info/lfs {
	client_max_body_size 0; # unlimited upload/download size
	include /etc/nginx/fastcgi_param # might be different base on your disto
	fastcgi_pass_request_headers on;
	fastcgi_pass unix:/var/lib/git-lfs-server/run/git-lfs-server.sock
}
```

### Apache

TODO

### OpenBSD httpd

OpenBSD httpd is a bit more tricky as the default webserver is chroot'ed to /var/www and
the FastCGI socket must be located inside the webserver chroot.

First, create a directory for the git-lfs socket:
```
install -d -m 0711 -o git-lfs -g git-lfs /var/www/run/git-lfs-server
```

In the global configuration /etc/git-lfs-server/git-lfs-server.conf, we should
define the process_chroot and fastcgi_socket option to point to within the /var/www/ chroot:
```
process_chroot "/var/www/run/git-lfs-server"
fastcgi_socket "/var/www/run/git-lfs-server/git-lfs-server.sock"
```

Finally, we can adjust our /etc/httpd.conf to something like this:
```
ext_ip="0.0.0.0"
server "example.com" {
        listen on $ext_ip port 80
		location match "/foo/bar.git/info/lfs/(.*)" {
		    connection {
		            max request body 1073741824 # set to any limit
		    }
		    fastcgi socket "/run/git-lfs-server/git-lfs-server.sock"
		}
}
```

## Repository data format

Git LFS repository objects are stored at the path defined by the "root" configuration option in the repository definition.
Each object is categorized into folders based on the object id (SHA256), with the first 2 characters of the object id
as the folder name.

Example layout (if "root" is set to /var/lib/git-lfs-server/foo/bar.git/lfs):

	/var
	  /lib
	    /git-lfs-server
	      /foo
	        /bar.git
	          /lfs
	           /1a
	             /a235b3f3..
	             /b373c7ae..
	           /2b
	             /a669937b..
	           /tmp
	           /locks
	             /locks.db

A tmp directory exists for temporary files and while files should not linger in here when server is shutdown, 
they can be cleared when the server is shutdown.

The locks/locks.db file is a database for all Git LFS locks. It can be deleted if it is necessary to force removal
of all locks or to fix a corrupted database.
