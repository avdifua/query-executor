# query-executor
Query executor on DB clusters hosts via ssh


Simple tool for connecting to the database host (master) and executing queries on Mysql.

Requirements. 
User name for connecting via ssh.
Password for the user.
Database user for connecting to Mysql.
Password for the database user.

And two files, with hosts and queries. Keys -hosts, -queries.

How it works.

1. Read files with hosts and queries.
2. Connect to the host via SSH and execute a query.

The tool can log in to Mysql with DBA user\password and external authentication (External authentication: PAM authentication enables MySQL Server to accept connections from users defined outside the MySQL grant tables and that authenticate using methods supported by PAM).
The first attempt to connect with DBA credentials and the second as a system user.

The query will be executed only on DB master host with classic replication type (master-slave).
If the tool detects the host is a replica or type of replication master-master, the query will not be executed. 

Why that? Because if the type of replication master-master and we execute a query on one master (for example drop user) we will break replication. 
In addition, I can add executing queries on slaves but now I do not need this at this time =)

This tool will be helping if you administrate a lot of databases clusters and for example need to add your new teammate to these clusters.

But be careful! The tool works asynchronously and very fast and you can break your database clusters for 1 sec =) 
Check queries you will be executed!

Enjoy! 
