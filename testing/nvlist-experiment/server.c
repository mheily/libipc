#include <err.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/nv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int setup_listen_socket()
{
    struct sockaddr_un name;
        char path[PATH_MAX];
        int len;
        int sockfd;

        len = snprintf(path, sizeof(path), "%s/foo.sock", "/usr/home/mark/tmp");
        if (len >= sizeof(path) || len < 0) {
                err(1, "buffer allocation error");
        }

        name.sun_family = AF_LOCAL;
        strncpy(name.sun_path, path, sizeof(name.sun_path));

        sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
        if (!sockfd)
                err(1, "socket");

        if (bind(sockfd, (struct sockaddr *) &name, SUN_LEN(&name)) < 0)
                err(1, "bind");

        if (listen(sockfd, 1024) < 0)
                err(1, "listen");

        return sockfd;
}

int accept_connection(int server)
{
    struct sockaddr sa;
    socklen_t sa_len;
    int client;

    client = accept(server, &sa, &sa_len);
    if (client < 0) {
            //rv = IPC_CAPTURE_ERRNO;
            //log_errno("accept(2)");
            return -1;
    }

    return client;
}

int main() {
     nvlist_t *nvl;
     const char	*command;
     char *filename;
     int fd, client, server;

     server = setup_listen_socket();
     client = accept_connection(server);
     if (client < 0) err(1, "bad client");

     nvl = nvlist_recv(client, 0);
     if	(nvl ==	NULL)
	     err(1, "nvlist_recv() failed");

     /*	For command we take pointer to nvlist's	buffer.	*/
     command = nvlist_get_string(nvl, "command");
     /*
      *	For filename we	remove it from the nvlist and take
      *	ownership of the buffer.
      */
     filename =	nvlist_take_string(nvl,	"filename");
     /*	The same for the descriptor. */
     fd	= nvlist_take_descriptor(nvl, "fd");

     printf("command=%s	filename=%s fd=%d", command, filename, fd);

     nvlist_destroy(nvl);
     free(filename);
     close(fd);
     puts("awesome");
}
