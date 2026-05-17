/*
 *    HardInfo - Displays System Information
 *    Copyright (C) 2003-2009 L. A. F. Pereira <l@tia.mat.br>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, version 2 or later.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <pwd.h>
#include "hardinfo.h"
#include "computer.h"

gint comparUsers (gpointer a, gpointer b) {return strcmp( (char*)a, (char*)b );}

gchar *users = NULL;

static unsigned atou(char **s)
{
	unsigned x;
	for (x=0; (unsigned)(**s-'0')<10U; ++*s) x=10*x+(**s-'0');
	return x;
}

int __hardinfo_getpwent_a(FILE *f, struct passwd *pw, char **line, size_t *size, struct passwd **res)
{
	ssize_t l;
	char *s;
	int rv = 0;
	//int cs;
	//pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	for (;;) {
		if ((l=getline(line, size, f)) < 0) {
			rv = ferror(f) ? errno : 0;
			free(*line);
			*line = 0;
			pw = 0;
			break;
		}
		line[0][l-1] = 0;

		s = line[0];
		pw->pw_name = s++;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_passwd = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_uid = atou(&s);
		if (*s != ':') continue;

		*s++ = 0; pw->pw_gid = atou(&s);
		if (*s != ':') continue;

		*s++ = 0; pw->pw_gecos = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_dir = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_shell = s;
		break;
	}
	//pthread_setcancelstate(cs, 0);
	*res = pw;
	if (rv) errno = rv;
	return rv;
}

static FILE *f;
static char *line;
static struct passwd pw;
static size_t size;

struct passwd *hardinfo_getpwent()
{
	struct passwd *res;
#if(HARDINFO2_FLATPAK)
	if (!f) f = fopen("/run/host/etc/passwd", "rbe");
#else
	if (!f) f = fopen("/etc/passwd", "rbe");
#endif
	if (!f) return 0;
	__hardinfo_getpwent_a(f, &pw, &line, &size, &res);
	return res;
}


void scan_users_do(void)
{
    struct passwd *passwd_;
    GList *list=NULL, *a;

    passwd_ = hardinfo_getpwent();
    if (!passwd_) return;

    if (users) {
        g_free(users);
        moreinfo_del_with_prefix("COMP:USER");
    }

    users = g_strdup("");

    while (passwd_) {
        gchar *key = g_strdup_printf("USER%s", passwd_->pw_name);
        gchar *val = g_strdup_printf("[%s]\n"
				     "%s=%d\n"
				     "%s=%d\n"
				     "%s=%s\n"
				     "%s=%s\n",
				     _("User Information"),
				     _("User ID"), (gint) passwd_->pw_uid,
				     _("Group ID"), (gint) passwd_->pw_gid,
				     _("Home Directory"), passwd_->pw_dir,
				     _("Default Shell"), passwd_->pw_shell);

        strend(passwd_->pw_gecos, ',');
        list = g_list_prepend(list, g_strdup_printf("%s,%s,%s,%s,%d", key, passwd_->pw_name, passwd_->pw_gecos, val, passwd_->pw_uid));
        passwd_ = getpwent();
        g_free(key);
        g_free(val);
    }

    endpwent();

    //sort
    list=g_list_sort(list,(GCompareFunc)comparUsers);


    while (list) {
        char **datas = g_strsplit(list->data,",",5);
        if (datas[0]) {
	    users = h_strdup_cprintf("$%s$%s=%s|%s\n", users, datas[0], datas[1], datas[2], datas[4]);
	    moreinfo_add_with_prefix("COMP", datas[0], g_strdup(datas[3]));
	}
	g_strfreev(datas);

        //next and free
        a=list;
        list=list->next;
        free(a->data);
        g_list_free_1(a);
    }

}
