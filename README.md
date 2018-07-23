# Git LFS FastCGI Server

*Warning: Not production ready*

This is an implementation of a FastCGI GIT LFS server using the v1 batch API.

This server is designed to be used when Git repositories are already hosted over HTTP 
using an existing webserver and you want to add LFS support. It is a FastCGI binary
that should interface with most webservers after a bit of configuration.

## TODO

* Test suite

## Limitations

This server does not read information about the git repositories that it serves.
Therefore it has no concept of user permissions on the actual repositories nor 
does it know the contents of a repository. This generally affects things such as
file locking, where anyone with repostory access can freely lock any files including
ones that don't exist!

## Building from source

Install the following dependancies:
 * cmake
 * bison/flex
 * libfcgi
 * json-c
 * sqlite3
 * openssl
 * zlib

On Debian, you can use apt to install the dependancies:
```
apt install cmake bison flex libssl-dev libfcgi-dev libsqlite3-dev libjson-c-dev libz-dev
```

Create a build directory:
```
mkdir builddir
cd builddir
```

Run cmake to generate the build files (replacing the path below to the root of the source code):
```
cmake path/to/git-lfs-fcgi
```

Build the code:
```
cmake --build .
```

For the first time, you must create the "git-lfs" user and group.

```
sudo groupadd git-lfs
sudo useradd git-lfs
```

Also create the /var/lib/git-lfs-fcgi/run directory and make them accessible by the git-lfs user.

```
sudo install -d -m 0755 -o git-lfs -g git-lfs /var/lib/git-lfs-fcgi
sudo install -d -m 0755 -o git-lfs -g git-lfs /var/lib/git-lfs-fcgi/run
```


## Configuration

The GIT-LFS server requires a configuration file to operate.

For example, if you run a GIT repository at https://git-server.com/foo/bar.git and you want to serve
a LFS server on https://git-server.com/foo/bar.git/info/lfs and you want to store your LFS objects
in the directory /var/lib/git-lfs-fcgi/foo/bar.git/lfs.

Create a file at /etc/git-lfs-fcgi/git-lfs-fcgi.conf and the configuration might look like this:

```
base_url "https://git-server.com"
chroot_path "/var/lib/git-lfs-fcgi"
repo "Foobar Repository"
{
	uri "/foo/bar.git/info/lfs"
	root "/var/lib/git-lfs-fcgi/foo/bar.git/lfs"
}
```

See examples in the conf/ directory for more ways to configure your repositories.

Man pages located in man/ fully document the configuration files.

See:

[git-lfs-fcgi.conf (5)](man/git-lfs-fcgi.conf.txt)

[git-lfs-fcgi (8)](man/git-lfs-fcgi.txt)

## FastCGI configuration

A webserver should be configured to pass LFS request to the FastCGI server.
The webserver is ideally be secured with HTTPS and authentication.

Using the example of handling https://git-server.com/foo/bar.git/info/lfs,
the webserver should now be configured to listen on the URI /foo/bar.git/info/lfs
and have the request passed via FastCGI to the socket listening on

/var/lib/git-lfs-fcgi/run/git-lfs-fcgi.sock

Instructions for setting this up will vary depending on the webserver.

### NGINX

In your server configuration, you might add a location block that looks like this:

```
location /foo/bar.git/info/lfs {
	client_max_body_size 0; # unlimited upload/download size
	fastcgi_keep_conn on;
	include /etc/nginx/fastcgi_param # might be different based on your disto
	fastcgi_pass_request_headers on;
	fastcgi_pass unix:/var/lib/git-lfs-fcgi/run/git-lfs-fcgi.sock
}
```

### Apache

For Apache (v2.4+), edit the httpd.conf configuration file to load the proxy and proxy_fcgi module.

```
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so
```

On a Debian-like system, instead of changing the httpd.conf directly, you can enable this by:

```
cd /etc/apache2/mods-enabled
ln -s ../mods-available/proxy.load .
ln -s ../mods-available/proxy_fcgi.load .
```

Edit your vhost configuration to include:
```
<VirtualHost *:80>
 	# etc...

	ProxyPass "/foo/bar.git/info/lfs/" "unix:/var/lib/git-lfs-fcgi/run/git-lfs-fcgi.sock|fcgi://localhost/" enablereuse=on

</VirtualHost>

```

### OpenBSD httpd

OpenBSD httpd is a bit more tricky as the default webserver is chroot'ed to /var/www and
the FastCGI socket must be located inside the webserver chroot.

First, create a directory for the git-lfs socket:
```
install -d -m 0711 -o git-lfs -g git-lfs /var/www/run/git-lfs-fcgi
```

In the global configuration /etc/git-lfs-fcgi/git-lfs-fcgi.conf, we should
define the process_chroot and fastcgi_socket option to point to within the /var/www/ chroot:
```
process_chroot "/var/www/run/git-lfs-fcgi"
fastcgi_socket "/var/www/run/git-lfs-fcgi/git-lfs-fcgi.sock"
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
		fastcgi socket "/run/git-lfs-fcgi/git-lfs-fcgi.sock"
	}
}
```

## Running the server

Pre-running checklist.

1) Make sure /etc/git-lfs-fcgi/git-lfs-fcgi.conf is setup

2) Make sure the base_url in the global configuration is properly set. If incorrectly set, this
may result in upload / download failures.

3) Web server configured with FastCGI. Ensure that request size limits are good.

4) Run the git-lfs FastCGI server

```
sudo /path/to/git-lfs-fcgi
```

By default, git-lfs-fcgi runs in the foreground but you can use the shell & to background the process.

```
sudo /path/to/git-lfs-fcgi &
```

On systemd systems, there is a conf/git-lfs-fcgi.service file which you can copy into your /etc/systemd/system folder.
Then you can start the server systemd style:

```
systemctl git-lfs-fcgi start
```


## Client setup

If you have a Git repository setup at https://git-server.com/foo/bar.git and you have followed the instructions
to setup Git LFS to listen on https://git-server.com/foo/bar.git/info/lfs, there is no additional client configuration.
GIT LFS clients will automatically detect LFS servers setup with /info/lfs appended to the repository URL.
This is the most ideal way to setup your GIT LFS server.

For custom URLs, set the lfs.url property on your repositories. For example:

```
git config lfs.url https://git-server.com/foo/bar.git/info/lfs
```

## Repository data format

Git LFS repository objects are stored at the path defined by the "root" configuration option in the repository definition.
Each object is categorized into folders based on the object id (SHA256), with the first 2 characters of the object id
as the folder name.

Example layout (if "root" is set to /var/lib/git-lfs-fcgi/foo/bar.git/lfs):

	/var
	  /lib
	    /git-lfs-fcgi
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
