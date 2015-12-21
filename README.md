# zipzapzop
A lightweight IPC mechanism.

The basic idea:

  Zip -- process A talks to zzzd, passes an AF_LOCAL socket, and requests access to
         a procedure (E.g. processb.hello_world)

  Zap -- zzzd talks to process B, passes the socket along, and adds some information
 	 about credentials (UID, GID, and process ID)

  Zop -- process B replies directly to process A using the AF_LOCAL socket. 

For improved performance, eventually everything that zzzd does would be moved into the kernel.
