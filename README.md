# Git LFS Server

*Warning: Not production ready*

This is an implementation of a FastCGI GIT LFS server using the v1 batch API.

This server is designed to serve multiple respositories and is a FastCGI binary
to plug into an existing webserver. Running as a standlone server is supported as well.

# TODO

* SSH authentication tool
* Support permissions on Git LFS locks
* Test suite

## Building from source

```
cmake
make
```

For the first time, you must create the "git-lfs" user and group.

```
sudo groupadd git-lfs
sudo useradd git-lfs
```

Also create the /var/lib/git-lfs-server directory.

```
sudo mkdir /var/lib/git-lfs-server
sudo mkdir /var/lib/git-lfs-server/run
sudo chown -R git-lfs:git-lfs /var/lib/git-lfs-server
```


## Configuration

The GIT-LFS server requires a configuration file to operate.

For example, if you run a GIT repository at https://git-server.com/foo/bar.git and you want to serve
a LFS server on https://git-server.com/foo/bar.git/info/lfs and you want to store your LFS objects
in the directory /var/lib/git-lfs-server/foo/bar.git/lfs.

Create a file at /etc/git-lfs-server/git-lfs-server.conf and the configuration might look like this:


```
base_url "https://git-server.com"
chroot_dir "/var/lib/git-lfs-server"
repo "Foobar Repository"
{
	uri "/foo/bar.git/info/lfs"
	root "/var/lib/git-lfs-server/foo/bar.git/lfs"
}
```

See examples in the conf/ directory for more ways to configure your repositories.

Man pages located in man/ fully document the configuration files.

See:

[man git-lfs-server (8)](man/git-lfs-server.html)
[man git-lfs-server (5)](man/git-lfs-server.conf.html)

Can be used when manpages are installed into the system.

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
