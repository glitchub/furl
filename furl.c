#define _GNU_SOURCE // for asprintf
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>

#define die(...) fprintf(stderr,__VA_ARGS__), exit(1)

#define OOM(s) if (!(s)) die("Out of memory\n")

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
    -s          - Verify HTTPS signature\n\
    -t seconds  - Set transaction timeout\n\
    -z          - Output debug data\n\
\n\
See https://github.com/glitchub/furl/blob/master/README for more details.\n\
");
}

// This is called for each response header line. Scrape the HTTP status from header
// "HTTP/xxx NNN reason". Note there may be multiple of these, we always want the last.
char *status = NULL; // Points to "NNN reason"
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
            int end = bytes;  // find last non-whitespace
            while (end > start && isspace(data[end-1])) end--;
            if (status) free(status);
            OOM(asprintf(&status, "%.*s", end - start, data + start) > 0);
        }
    }
    return size;
}

#define curlopt(curl,opt,arg) do { CURLcode res = curl_easy_setopt(curl,opt,arg); if (res) die(#opt ": %s\n", curl_easy_strerror(res)); } while (0)

int main(int argc, char *argv[])
{
    int post = 0;
    bool follow = false;
    char *pin = NULL;
    bool validate = false;
    char *timeout = NULL;
    bool debug = false;

    while(1) switch(getopt(argc, argv,":dfp:st:z"))
    {
        case 'd': post++; break;            // Once = post raw, twice = post url-encoded
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
    curlopt(curl, CURLOPT_HEADERFUNCTION, header_callback); // extracts the HTTP status string

    if (post)
    {
        // slurp stdin
        char *input = NULL;
        size_t size = 0;
        while (true)
        {
            #define CHUNK 8192
            input = input ? realloc(input, size+CHUNK) : malloc(CHUNK);
            OOM(input);
            size_t got = fread(input+size, 1, CHUNK, stdin);
            if (!got) break;
            size += got;
        }

        if (!size) free(input);
        else if (post == 1)
        {
            // send binary, note *input must not be freed
            curlopt(curl, CURLOPT_POSTFIELDSIZE, size);
            curlopt(curl, CURLOPT_POSTFIELDS, input);
            curlopt(curl, CURLOPT_POST, 1);
        } else
        {
            // send url-encoded, note *encoded must not be freed
            char *encoded = curl_easy_escape(curl, input, size);
            OOM(encoded);
            free(input);
            curlopt(curl, CURLOPT_POSTFIELDS, encoded); // will invoke strlen()
            curlopt(curl, CURLOPT_POST, 1);
        }
    }

    if (follow) curlopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    if (pin)
    {
        char *s;
        OOM(asprintf(&s, "sha256//%s", pin) > 0); // pre-pend the magic header
        curlopt(curl, CURLOPT_PINNEDPUBLICKEY, s);
        free(s);
    }

    if (!validate)
    {
        curlopt(curl, CURLOPT_SSL_VERIFYHOST, 0); // ignore signatures
        curlopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curlopt(curl, CURLOPT_CAINFO, NULL); // don't bother to load certs
    }

    if (timeout)
    {
        char *e;
        unsigned long t = strtoul(timeout, &e, 10);
        if (!t || *e) die("Invalid timeout '%s'\n", timeout);
        curlopt(curl, CURLOPT_TIMEOUT, t);
    }

    if (debug) curlopt(curl, CURLOPT_VERBOSE, 1);

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
