#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/nv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int setup_client_socket() {
	char statedir[PATH_MAX];
	struct sockaddr_un sock;
	int len, fd;

	sock.sun_family = AF_LOCAL;
	len = snprintf(sock.sun_path, sizeof(sock.sun_path), "%s/foo.sock", "/usr/home/mark/tmp");

	if (len >= sizeof(sock.sun_path)) {
		//client->last_error = -IPC_ERROR_NAME_TOO_LONG;
		return -1;
	}
	if (len < 0) {
		//client->last_error = IPC_CAPTURE_ERRNO;
		return -1;
	}

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		//client->last_error = IPC_CAPTURE_ERRNO;
		//log_errno("socket(2)");
		return -1;
	}

	if (connect(fd, (struct sockaddr *) &sock, SUN_LEN(&sock)) < 0) {
		//client->last_error = IPC_CAPTURE_ERRNO;
		//log_errno("connect(2) to %s", sock.sun_path);
		return -1;
	}

	return fd;
}

int main() {
	nvlist_t *nvl;
    int fd;
    int sock;

    sock = setup_client_socket();
    if (sock < 0) err(1, "socket failed");

     fd	= open("/tmp/foo", O_RDONLY);
     if	(fd < 0)
	     err(1, "open(\"/tmp/foo\")	failed");

     nvl = nvlist_create(0);
     /*
      *	There is no need to check if nvlist_create() succeeded,
      *	as the nvlist_add_<type>() functions can cope.
      *	If it failed, nvlist_send() will fail.
      */
     nvlist_add_string(nvl, "command",	"hello");
     nvlist_add_string(nvl, "filename",	"/tmp/foo");
     nvlist_add_number(nvl, "flags", O_RDONLY);
     /*
      *	We just	want to	send the descriptor, so	we can give it
      *	for the	nvlist to consume (that's why we use nvlist_move
      *	not nvlist_add).
      */
     nvlist_move_descriptor(nvl, "fd", fd);
     if	(nvlist_send(sock, nvl)	< 0) {
	     nvlist_destroy(nvl);
	     err(1, "nvlist_send() failed");
     }
     nvlist_destroy(nvl);
}
