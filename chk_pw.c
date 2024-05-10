#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>

#include <stdint.h>
typedef uint8_t u8;

#include <unistd.h>
#include <termios.h>
#include <limits.h>

#include <pwd.h>
#include <security/pam_appl.h>

#define DEFAULT_GETPW_R_SIZE_MAX ((LOGIN_NAME_MAX + 1) + 4096 * 4)
#define MAX_PASS_BUF_LEN 4096


// 0 = success, -1 = error
int8_t get_user_input(size_t bufsize, char *buf, u8 do_echo) {
    // {{{
    int8_t ret_code = -1;
    struct termios term;

    if (do_echo == 0) {
        if (tcgetattr(fileno(stdin), &term) != 0) return -1;
        term.c_lflag &= ~ECHO; // Set echo to off
        if (tcsetattr(fileno(stdin), TCSANOW, &term) != 0) return -1;
    }

    if (fgets(buf, bufsize, stdin) != NULL)
         ret_code = 0;
    else ret_code = -1;

    if (do_echo == 0) {
        term.c_lflag |= ECHO; // Turn echo back on
        if (tcsetattr(fileno(stdin), TCSANOW, &term) != 0) return -1;
        (void) putchar('\n');
    }

    return ret_code;
} // }}}

int pam_conversation_fn(
    int num_msg,
    const struct pam_message **msg,
    struct pam_response **res,
    void *appdata_ptr);


int main(int argc, char **argv) {
    if ( (argc - 1) != 1 ) {
        (void) fprintf(stderr, "Wrong num of args! (%d != 1 : uid)\n", (argc - 1));
        return 1;
    }


    uid_t uid;
    // Parse uid
    if (sscanf(argv[1], "%u", &uid) != 1) {
        (void) fprintf(stderr, "Failed to read in uid\n");
        return 1;
    }

    char username[LOGIN_NAME_MAX + 1];
    username[LOGIN_NAME_MAX] = '\0';
    // Get username {{{
    {
        u8 username_ok = 0;
        {
            struct passwd pw, *result_ptr;

            // Ask system for max passwd entry length
            ssize_t query_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (query_bufsize == -1)
                query_bufsize = DEFAULT_GETPW_R_SIZE_MAX;

            const size_t buflen = query_bufsize;
            char str_buf[buflen];

            // Ignore return value, we just check for NULL in result_ptr
            (void) getpwuid_r(uid, &pw, str_buf, buflen, &result_ptr);

            if (result_ptr != NULL) {
                (void) strncpy(username, pw.pw_name, LOGIN_NAME_MAX);
                username_ok = 1;
            }
        }

        if (username_ok != 1) {
            (void) fprintf(stderr, "Failed to get username with getpwuid_r\n");
            return 1;
        }
    }
    // }}}

    u8 auth_ok = 0;
    // PAM {{{
    {
        pam_handle_t *pam_handle;
        int ret;

        // Init
        struct pam_conv conv = {
            .conv = pam_conversation_fn,
            .appdata_ptr = NULL
        };

        ret = pam_start("passwd", username, &conv, &pam_handle);

        if (ret != PAM_SUCCESS) {
            (void) fprintf(stderr, "pam_start failed: %d\n", ret);
            return 1;
        }

        // Authenticate
        ret = pam_authenticate(pam_handle, PAM_DISALLOW_NULL_AUTHTOK);

        if (ret == PAM_ABORT) {
            (void) fprintf(stderr, "pam_authenticate failed: %d\n", ret);

            ret = pam_end(pam_handle, ret);
            if (ret != PAM_SUCCESS)
                (void) fprintf(stderr, "pam_end failed: %d\n", ret);

            return 1;
        }

        if (ret == PAM_SUCCESS)
             auth_ok = 1;
        else (void) fprintf(stderr, "pam_authenticate failed: %d\n", ret);

        // End
        ret = pam_end(pam_handle, ret);

        if (ret != PAM_SUCCESS) {
            (void) fprintf(stderr, "pam_end failed: %d\n", ret);
            return 1;
        }
    }
    // }}}


    if (auth_ok == 1)
         return EXIT_SUCCESS;
    else return EXIT_FAILURE;
}


int pam_conversation_fn(
        int num_msg,
        const struct pam_message **msgs,
        struct pam_response **resps_ptr,
        void *custom_data) {
    (void)(&custom_data); // Explicitly ignore unused param
    struct pam_response *resps = calloc(num_msg, sizeof(struct pam_response));

    if (resps == NULL)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i += 1) {
        const struct pam_message *msg = msgs[i];

        struct pam_response *resp = &resps[i];
        resp->resp_retcode = 0;
        resp->resp = NULL;

        if (msg->msg_style == PAM_TEXT_INFO) {
            // Print a message {{{
            if (printf("%s\n", msg->msg) < 0) {
                free(resps);
                return PAM_CONV_ERR;
            }
            // }}}

        } else if (msg->msg_style == PAM_ERROR_MSG) {
            // Display an error {{{
            if (fprintf(stderr, "[E]: %s\n", msg->msg) < 0) {
                free(resps);
                return PAM_CONV_ERR;
            }
            // }}}

        } else if (msg->msg_style == PAM_PROMPT_ECHO_ON
                || msg->msg_style == PAM_PROMPT_ECHO_OFF) {
            // Get string from user {{{
            u8 do_echo = 0;
            if (msg->msg_style == PAM_PROMPT_ECHO_ON) do_echo = 1;

            // Prompt
            if (printf("%s", msg->msg) < 0) {
                free(resps);
                return PAM_CONV_ERR;
            }

            u8 read_ok = 0;
            char pass_buf[MAX_PASS_BUF_LEN + 1];
            pass_buf[MAX_PASS_BUF_LEN] = '\0';

            if (get_user_input(MAX_PASS_BUF_LEN, pass_buf, do_echo) == 0)
                read_ok = 1;

            if (read_ok == 0) {
                free(resps);
                return PAM_CONV_ERR;
            }

            // Check for \n before \0 and replace
            for (size_t j = 1; j < (MAX_PASS_BUF_LEN + 1); j += 1) {
                if (pass_buf[j] == '\0' && pass_buf[j-1] == '\n') {
                    pass_buf[j-1] = '\0';
                    break;
                }
            }

            size_t pass_len = strnlen(pass_buf, MAX_PASS_BUF_LEN);
            resp->resp = malloc(pass_len + 1);
            resp->resp[pass_len] = '\0';
            (void) memcpy(resp->resp, pass_buf, pass_len);
        } // }}}
    }

    *resps_ptr = resps;
    return PAM_SUCCESS;
}
