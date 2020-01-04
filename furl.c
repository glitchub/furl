#define _GNU_SOURCE # allow aprintf
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>

#define die(...) fprintf(stderr,__VA_ARGS__), exit(1)

#define OOM(s) if (!s) die("Out of memory\n")

static void usage(void)
{
    die("Usage:\n\
\n\
    furl [options] URL\n\
\n\
Options are:\n\
\n\
    -d          - POST data from stdin (use twice to url-encode it)\n\
    -f          - Follow HTTP redirects\n\
    -p pin      - Use pinned HTTPS public key\n\
    -s          - Verify HTTPS public key\n\
    -t seconds  - Set transaction timeout\n\
    -z          - Output debug data\n\
\n\
See https://github/glitchub/furl/README for more details.\n\
");
}

// This is called for each response header line. Scrape the HTTP status from header
// "HTTP/xxx NNN reason". Note there may be multiple of these, we always want the last.
char *status = NULL;    // Contains the "NNN reason"
int header_callback(char *data, size_t size, size_t nmemb, void *user)
{
    (void) user;
    size_t bytes = size *= nmemb;
    if (bytes > 5 && !strncmp(data,"HTTP/",5))
    {
        int start=5;
        while (start < bytes && !isspace(data[start])) start++;
        while (start < bytes && isspace(data[start])) start++;
        if (start < bytes)
        {
            int end=bytes;  // find last non-whitespace
            while (end > start && isspace(data[end-1])) end--;
            if (status) free(status);
            if (asprintf(&status, "%.*s", end - start, data + start) < 0) die("Out of memory!\n");
        }
    }
    return size;
}

#define curlopt(curl,opt,arg) do { CURLcode res = curl_easy_setopt(curl,opt,arg); if (res) die(#opt ": %s\n", curl_easy_strerror(res)); } while(0)

int main(int argc, char *argv[])
{
    bool validate = false;
    char *pin = NULL;
    int post = 0;
    bool follow = false;
    bool debug = false;
    char *timeout = NULL;

    while(1) switch(getopt(argc, argv,":dfp:st:z"))
    {
        case 'd': post++; break;
        case 'f': follow = true; break;
        case 'p': pin = optarg; break;
        case 's': validate = true; break;
        case 't': timeout = optarg; break;
        case 'z': debug = true; break;
        case ':':                           // missing
        case '?': usage();                  // invalid option
        case -1: goto optx;
    } optx:
    if (optind >= argc) usage();

    char *url = argv[optind];

    CURL *curl = curl_easy_init();
    if (!curl) die("curl_easy_init: failed\n");

    curlopt(curl, CURLOPT_URL, url);
    curlopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);

    if (follow) curlopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    if (!validate)
    {
        curlopt(curl, CURLOPT_SSL_VERIFYHOST, 0);   // ignore signatures
        curlopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curlopt(curl, CURLOPT_CAINFO, NULL);        // don't bother to load certs
    }

    if (pin)
    {
        char *s;
        if (asprintf(&s, "sha256//%s", pin) < 0) die("Out of memory!\n");   // pre-pend the magic header
        curlopt(curl, CURLOPT_PINNEDPUBLICKEY, s);
        free(s);
    }

    if (post)
    {
        // slurp stdin
        char *input = malloc(8192);
        OOM(input);
        size_t size = 0;
        while(1)
        {
            size_t got = fread(input+size, 1, 8192, stdin);
            if (!got) break;
            size += got;
            input=realloc(input, size+8192);
            OOM(input);
        }

        curlopt(curl, CURLOPT_POST, 1);
        if (post == 1)
        {
            // send binary, set size before copypostfields
            curlopt(curl, CURLOPT_POSTFIELDSIZE, size);
            curlopt(curl, CURLOPT_COPYPOSTFIELDS, input);
        } else
        {
            // send url-encoded
            char *encoded = curl_easy_escape(curl, input, size);
            OOM(encoded);
            curlopt(curl, CURLOPT_COPYPOSTFIELDS, encoded); // will invoke strlen()
            curl_free(encoded);
        }
        free(input);
    }

    if (timeout)
    {
        char *e;
        unsigned long t = strtoul(timeout, &e, 10);
        if (!t || *e) die("Invalid timeout '%s'\n", timeout);
        curlopt(curl, CURLOPT_TIMEOUT, t);
    }

    if (debug) curlopt(curl, CURLOPT_VERBOSE, 1);

    curlopt(curl, CURLOPT_HEADERFUNCTION, header_callback); // extracts the HTTP status string

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res) die("%s\n", curl_easy_strerror(res));

    if (!status || *status != '2')
    {
        fflush(stdout);
        fprintf(stderr, "HTTP status '%s'\n", status ?: "unknown");
        return 2;
    }

    return 0;
}
