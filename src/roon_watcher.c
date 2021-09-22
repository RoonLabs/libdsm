/* Netbios Discover */
/* originally copied from libdsm example code */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "bdsm.h"

struct credentials
{
    char *workgroup;
    char *username;
    char *password;
};

static void print_entry(const char *what, void *p_opaque,
                        netbios_ns_entry *entry)
{
    struct in_addr addr;

    addr.s_addr = netbios_ns_entry_ip(entry);

    printf("%s(%p): Ip: %s, name: %s/%s<%x>\n",
           what,
           p_opaque,
           inet_ntoa(addr),    netbios_ns_entry_group(entry),
           netbios_ns_entry_name(entry),
           netbios_ns_entry_type(entry));
}

static int list_shares(void *p_opaque,
                       netbios_ns_entry *entry)
{
    struct credentials *creds = (struct credentials *)p_opaque;
    struct in_addr  addr;
    smb_session   *session;
    smb_tid     tid;
    smb_fd      fd;

    session = smb_session_new();
    if (session == NULL)
        return 1;

    addr.s_addr = netbios_ns_entry_ip(entry);

    if (smb_session_connect(session, netbios_ns_entry_name(entry), 
                            addr.s_addr, SMB_TRANSPORT_TCP))
    {
        printf("Unable to connect to host %s\n", inet_ntoa(addr));
        return 2;
    }

    smb_session_set_creds(session, creds->workgroup, creds->username, creds->password);
    int login_ret = smb_session_login(session);
    if (login_ret == DSM_SUCCESS)
    {
        if (smb_session_is_guest(session))
            printf("Logged in as GUEST\n");
        else
            printf("Successfully logged in\n");
    }
    else
    {
        printf("Auth failed %s\n", inet_ntoa(addr));
        return 3;
    }

    smb_share_list list;
    size_t count;
    int list_ret = smb_share_get_list(session, &list, &count);
    if (list_ret == DSM_SUCCESS)
    {
        printf("    share count: %i\n", count);
    }
    else
    {
        printf("Unable to connect to share, ret value: %i\n", list_ret);
        if (list_ret == DSM_ERROR_NT)
        {
            uint32_t nt_status = smb_session_get_nt_status(session);
            printf("nt_status: %x\n", nt_status);
        }
      
        return 4;
    }

    for (int i = 0; i < count; i++) {
        printf("    share name: %s\n", smb_share_list_at(list, i));
    }
  
    smb_share_list_destroy(list);
    smb_session_destroy(session);

    return 0;
}

static void on_entry_added(void *p_opaque,
                           netbios_ns_entry *entry)
{
    print_entry("added", p_opaque, entry);

    int list_ret = list_shares(p_opaque, entry);
}

static void on_entry_removed(void *p_opaque,
                             netbios_ns_entry *entry)
{
    print_entry("removed", p_opaque, entry);
}

int main(int argc, char** argv)
{
    struct credentials *args = malloc(sizeof(struct credentials));
    if (argc >= 4)
    {
        args->workgroup = argv[1];
        args->username  = argv[2];
        args->password  = argv[3];
    }
    else if (argc == 3)
    {
        args->workgroup = "";
        args->username  = argv[1];
        args->password  = argv[2];
    }
    else if (argc == 2)
    {
        args->workgroup = "";
        args->username  = argv[1];
        args->password  = "";
    }
    else if (argc == 1)
    {
        args->workgroup = "";
        args->username  = "";
        args->password  = "";
    }
  
    netbios_ns *ns;
    netbios_ns_discover_callbacks callbacks;

    ns = netbios_ns_new();

    callbacks.p_opaque = (void*)args;
    callbacks.pf_on_entry_added = on_entry_added;
    callbacks.pf_on_entry_removed = on_entry_removed;

    printf("Discovering...\nPress Enter to quit\n");
    int ret = netbios_ns_discover_start(ns,
                                        4, // broadcast every 4 sec
                                        &callbacks);
    printf("return code from start: %i\n", ret);
    if (ret != 0)
    {
        fprintf(stderr, "Error while discovering local network\n");
        exit(42);
    }

    getchar();

    netbios_ns_discover_stop(ns);

    return (0);
}
