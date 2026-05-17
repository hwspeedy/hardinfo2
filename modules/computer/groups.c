/*
 *    HardInfo - Displays System Information
 *    Copyright (C) 2012 L. A. F. Pereira <l@tia.mat.br>
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

#include <sys/types.h>
#include <grp.h>
#include "hardinfo.h"
#include "computer.h"

gint comparGroups (gpointer a, gpointer b) {return strcmp( (char*)a, (char*)b );}

gchar *groups = NULL;

static unsigned atou(char **s)
{
	unsigned x;
	for (x=0; (unsigned)(**s-'0')<10U; ++*s) x=10*x+(**s-'0');
	return x;
}

int __hardinfo_getgrent_a(FILE *f, struct group *gr, char **line, size_t *size, char ***mem, size_t *nmem, struct group **res)
{
	ssize_t l;
	char *s, *mems;
	size_t i;
	int rv = 0;
	//int cs;
	//pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	for (;;) {
		if ((l=getline(line, size, f)) < 0) {
			rv = ferror(f) ? errno : 0;
			free(*line);
			*line = 0;
			gr = 0;
			goto end;
		}
		line[0][l-1] = 0;

		s = line[0];
		gr->gr_name = s++;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; gr->gr_passwd = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; gr->gr_gid = atou(&s);
		if (*s != ':') continue;

		*s++ = 0; mems = s;
		break;
	}

	for (*nmem=!!*s; *s; s++)
		if (*s==',') ++*nmem;
	free(*mem);
	*mem = calloc(*nmem+1, sizeof(char *));
	if (!*mem) {
		rv = errno;
		free(*line);
		*line = 0;
		gr = 0;
		goto end;
	}
	if (*mems) {
		mem[0][0] = mems;
		for (s=mems, i=0; *s; s++)
			if (*s==',') *s++ = 0, mem[0][++i] = s;
		mem[0][++i] = 0;
	} else {
		mem[0][0] = 0;
	}
	gr->gr_mem = *mem;
end:
	//pthread_setcancelstate(cs, 0);
	*res = gr;
	if(rv) errno = rv;
	return rv;
}

static FILE *f;
static char *line, **mem;
static struct group gr;

struct group *hardinfo_getgrent()
{
	struct group *res;
	size_t size=0, nmem=0;
#if(HARDINFO2_FLATPAK)
	if (!f) f = fopen("/run/host/etc/group", "rbe");
#else
	if (!f) f = fopen("/etc/group", "rbe");
#endif
	if (!f) return 0;
	__hardinfo_getgrent_a(f, &gr, &line, &size, &mem, &nmem, &res);
	return res;
}

void scan_groups_do(void)
{
    struct group *group_;
    GList *list=NULL, *a;

    setgrent();
    group_ = hardinfo_getgrent();
    if (!group_)
        return;

    g_free(groups);
    groups = g_strdup("");

    while (group_) {
        gchar *members=NULL, **p;
        for(p=group_->gr_mem; *p != NULL; p++){
	    if(members)
	        members=h_strdup_cprintf(", %s", members, *p);
	    else
	        members=g_strdup(*p);
	}
	if(!members) members=g_strdup(_("None"));
        gchar *key = g_strdup_printf("GROUP%s", group_->gr_name);
        gchar *val = g_strdup_printf("[%s]\n"
		                     "%s=%s\n"
		                     "%s=%d\n"
		                     "%s=%s\n",
				     _("Group Information"),
				     _("Group Name"), group_->gr_name,
				     _("Group ID"), (gint) group_->gr_gid,
				     _("Members"), members);

        list=g_list_prepend(list,g_strdup_printf("%s,%s,%d,%s", key, group_->gr_name, group_->gr_gid, val));
        group_ = getgrent();
    }
    
    endgrent();

    //sort
    list=g_list_sort(list,(GCompareFunc)comparGroups);

    while (list) {
        char **datas = g_strsplit(list->data,",",4);
	if(datas[0]){
            groups = h_strdup_cprintf("$%s$%s=%s\n", groups, datas[0], datas[1], datas[2]);
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
