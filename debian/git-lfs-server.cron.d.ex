#
# Regular cron jobs for the git-lfs-server package
#
0 4	* * *	root	[ -x /usr/bin/git-lfs-server_maintenance ] && /usr/bin/git-lfs-server_maintenance
