#include <fcgiapp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

int main(int argc, char *argv[])
{
    const char socket[] = ":9000";
    int maxConnections = 400;

    static struct option longOptions[] =
    {
        { "help", no_argument, nullptr, 0 },
        { "socket", required_argument, nullptr, 0 },
        { "max-connections", required_argument, nullptr, 0 },
        {0, 0, 0, 0}
    };

    int optIndex;
    int c;
    while((c = getopt_long (argc, argv, "", longOptions, &optIndex)) > 0)
    {
        switch(optIndex) {
            case 0: /* help */
                break;
            case 1: /* socket */
                socket = optarg;
                break;
            case 2: /* max-connections */
                maxConnections = strtol(optarg, nullptr, 10);
                break;
        }
    }

	FCGX_Request request;

	FCGX_Init();

    int listeningSocket = FCGX_OpenSocket(socket, maxConnections);
	if(listeningSocket < 0) {
		fprintf(stderr, "Failed to create socket.");
		exit(1);
	}

	FCGX_InitRequest(&request, listeningSocket, 0);

	printf("Ready to serve...\n");
    while (FCGX_Accept_r(&request) == 0) {

		const char *requestMethod = FCGX_GetParam("REQUEST_METHOD", request.envp);
		const char *documentUri = FCGX_GetParam("DOCUMENT_URI", request.envp);
		const char *queryString = FCGX_GetParam("QUERY_STRING", request.envp);

		const char *endPoint = strrchr(documentUri, '/');
		if(endPoint) {
			git_lfs_server_handle_request(requestMethod, endPoint, request.envp);
		}

		FCGX_Finish_r(&request);
	}

    printf("Shutdown...\n");

	return 0;
}
