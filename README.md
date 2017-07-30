# Git LFS Server

*Warning: Not production ready*

This is a lightweight implementation of a GIT LFS server using the v1 batch API.
It can be run on it's own or as a FastCGI binary for use with an existing webserver.

## Building from source

```
cmake
make
```

## Running

```
git-lfs-server --config=/etc/git-lfs-server.conf
```

## Configuration file

The configuration file defines global settings for the server and a list of repositories.

### Global Settings

Global settings are defined here:

	base_url _url_
		Set the base URL of your web server. i.e. "https://git.mydomain.com"
		This will be the URL used for generating download and upload links for the
		Git LFS client to upload and download objects.

	port _number_
		The listening port number. Ignored in FastCGI mode.

	chroot_path _path_
		Optional chroot to a folder. Repository LFS objects will be contained to this folder.

	user _name_
		System username to run the server

	group _name_
		System group to run the server

	verify_upload [yes|no]
		Whether uploaded files are verified by comparing the SHA256 with the file contents before saving it.
		Default is true.

	num_threads _number_
		The number of worker threads to use. Increase to allow more concurrent connections.

	fastcgi_server [yes|no]
		Set to yes to enable FastCGI mode. Consult your web server documentation for setup instructions.

	fastcgi_socket _path_
		Path to the unix domain socket to use for FastCGI communication. If specified in the format of ":_port_",
		then listen on the port specified by _port_. This path is relative to the chroot path.

	include _path_
		Includes the specified path as part of the configuration. Supposes wildcards *.

### Repo Settings

A list of repositories can be defined in the config file in addition to the global settings.
Each repository block has the following format:

```
repo _name_
{
	# ... repository specific settings
}
```

For each repository, individual settings may be applied:

	uri _uri_
		Specify the URI for this repository.
		For eg.
			uri "/var/gitrepos/myrepo.git/info/lfs"
		If the _base_url_ is "https://www.example.com", then it will match
		the URL: "https://www.example.com/var/gitrepos/myrepo.git/info/lfs"

	root _path_
		The root path to store LFS objects for this repository, relative to the chroot_path.

	enable_authentication [yes|no]
		Whether built-in authentication is turned on for this repository. One reason to turn this off is
		if the webserver is handling the authentication when running as FastCGI.

	auth_realm _name_
		Authentication realm name. Optional.

	auth_file _path_
		Path to a passwd file which contains credentials for users to access this repository. The passwd
		file is created using the htpasswd utility from Apache and supports bcrypt passwords storage only.

