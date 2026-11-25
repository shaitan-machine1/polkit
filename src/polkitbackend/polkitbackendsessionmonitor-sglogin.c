/*
 * SGLogin session provider.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */
#include "config.h"
#include <errno.h>
#include <sglogin/login.h>
#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>
#include "polkitbackendsessionmonitor.h"

struct _PolkitBackendSessionMonitor
{
  GObject parent_instance;
  sgl_client *client;
  sgl_login_monitor *monitor;
  GSource *source;
};
struct _PolkitBackendSessionMonitorClass
{
  GObjectClass parent_class;
  void (*changed) (PolkitBackendSessionMonitor *monitor);
};
typedef struct
{
  GSource source;
  PolkitBackendSessionMonitor *owner;
  GPollFD polls[18];
  gsize count;
  gboolean buffered;
} SglSource;
G_DEFINE_TYPE (PolkitBackendSessionMonitor, polkit_backend_session_monitor, G_TYPE_OBJECT)

static void
provider_error (PolkitBackendSessionMonitor *monitor, const gchar *operation, int result, GError **error)
{
  const char *detail = monitor->client ? sgl_client_last_error (monitor->client) : "no client";
  if (error != NULL)
    g_set_error (error, POLKIT_ERROR, POLKIT_ERROR_FAILED,
                 "SGLogin %s: %s (%d)", operation, detail, -result);
  else
    g_debug ("SGLogin %s: %s (%d)", operation, detail, -result);
}
static gboolean
source_prepare (GSource *source, gint *timeout)
{
  SglSource *sgl = (SglSource *) source;
  sgl_poll_fd fds[18];
  int32_t buffered = 0, milliseconds = -1;
  size_t count = 0, i;
  int result;

  for (i = 0; i < sgl->count; i++)
    g_source_remove_poll (source, &sgl->polls[i]);
  sgl->count = 0;
  sgl->buffered = FALSE;
  result = sgl_login_monitor_prepare (sgl->owner->monitor, fds, G_N_ELEMENTS (fds),
                                    &count, &milliseconds, &buffered);
  if (result < 0)
    {
      provider_error (sgl->owner, "monitor prepare", result, NULL);
      *timeout = -1;
      return FALSE;
    }
  for (i = 0; i < count; i++)
    {
      sgl->polls[i].fd = fds[i].fd;
      sgl->polls[i].events = fds[i].events;
      sgl->polls[i].revents = 0;
      g_source_add_poll (source, &sgl->polls[i]);
    }
  sgl->count = count;
  sgl->buffered = buffered != 0;
  *timeout = milliseconds;
  return sgl->buffered;
}
static gboolean
source_check (GSource *source)
{
  SglSource *sgl = (SglSource *) source;
  gsize i;
  if (sgl->buffered)
    return TRUE;
  for (i = 0; i < sgl->count; i++)
    if (sgl->polls[i].revents != 0)
      return TRUE;
  return FALSE;
}
static gboolean
source_dispatch (GSource *source, GSourceFunc callback, gpointer data)
{
  SglSource *sgl = (SglSource *) source;
  int32_t changed = 0;
  int result;
  (void) callback;
  (void) data;
  result = sgl_login_monitor_dispatch (sgl->owner->monitor, 32, &changed);
  if (result < 0)
    provider_error (sgl->owner, "monitor dispatch", result, NULL);
  if (changed || result < 0)
    g_signal_emit_by_name (sgl->owner, "changed");
  return G_SOURCE_CONTINUE;
}
static GSourceFuncs source_funcs = {
  .prepare = source_prepare,
  .check = source_check,
  .dispatch = source_dispatch
};
static void
polkit_backend_session_monitor_finalize (GObject *object)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (object);
  if (monitor->source != NULL)
    {
      g_source_destroy (monitor->source);
      g_source_unref (monitor->source);
    }
  sgl_login_monitor_free (monitor->monitor);
  sgl_client_free (monitor->client);
  G_OBJECT_CLASS (polkit_backend_session_monitor_parent_class)->finalize (object);
}
static void
polkit_backend_session_monitor_class_init (PolkitBackendSessionMonitorClass *klass)
{
  G_OBJECT_CLASS (klass)->finalize = polkit_backend_session_monitor_finalize;
  g_signal_new ("changed", G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST,
                G_STRUCT_OFFSET (PolkitBackendSessionMonitorClass, changed),
                NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);
}
static void
polkit_backend_session_monitor_init (PolkitBackendSessionMonitor *monitor)
{
  int result = sgl_client_new (NULL, &monitor->client);
  if (result == 0)
    result = sgl_login_monitor_new (monitor->client, &monitor->monitor);
  if (result < 0)
    {
      provider_error (monitor, "monitor construction", result, NULL);
      return;
    }
  monitor->source = g_source_new (&source_funcs, sizeof (SglSource));
  ((SglSource *) monitor->source)->owner = monitor;
  g_source_set_name (monitor->source, "SGLogin session invalidations");
  g_source_attach (monitor->source, NULL);
}
PolkitBackendSessionMonitor *
polkit_backend_session_monitor_new (void)
{
  return g_object_new (POLKIT_BACKEND_TYPE_SESSION_MONITOR, NULL);
}
GList *
polkit_backend_session_monitor_get_sessions (PolkitBackendSessionMonitor *monitor)
{
  /* The authority does not use session enumeration; same contract as logind. */
  (void) monitor;
  return NULL;
}
PolkitIdentity *
polkit_backend_session_monitor_get_user_for_subject (PolkitBackendSessionMonitor *monitor,
                                                    PolkitSubject *subject,
                                                    gboolean *result_matches,
                                                    GError **error)
{
  PolkitIdentity *identity = NULL;
  gboolean matches = FALSE;
  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      gint uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (subject));
      gint actual;
      GError *local_error = NULL;
      if (uid == -1)
        {
          g_set_error (error, POLKIT_ERROR, POLKIT_ERROR_FAILED,
                       "Unix process subject does not have uid set");
          goto out;
        }
      actual = polkit_unix_process_get_racy_uid__ (POLKIT_UNIX_PROCESS (subject), &local_error);
      if (local_error != NULL)
        {
          g_propagate_error (error, local_error);
          goto out;
        }
      identity = polkit_unix_user_new (uid);
      matches = uid == actual;
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      identity = (PolkitIdentity *) polkit_system_bus_name_get_user_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                                         NULL, error);
      matches = TRUE;
    }
  else if (POLKIT_IS_UNIX_SESSION (subject))
    {
      uint32_t uid = 0;
      const gchar *sid = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (subject));
      int result = sgl_session_get_uid (monitor->client, sid, &uid);
      if (result < 0)
        provider_error (monitor, "session UID", result, error);
      else
        {
          identity = polkit_unix_user_new (uid);
          matches = TRUE;
        }
    }
out:
  if (result_matches != NULL)
    *result_matches = matches;
  return identity;
}
PolkitSubject *
polkit_backend_session_monitor_get_session_for_subject (PolkitBackendSessionMonitor *monitor,
                                                       PolkitSubject *subject,
                                                       GError **error)
{
  PolkitSubject *temporary = NULL, *session = NULL;
  PolkitUnixProcess *process;
  char *sid = NULL;
  gint pid;
  int result;
  if (POLKIT_IS_UNIX_PROCESS (subject))
    process = POLKIT_UNIX_PROCESS (subject);
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      temporary = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, error);
      if (temporary == NULL)
        goto out;
      process = POLKIT_UNIX_PROCESS (temporary);
    }
  else
    {
      g_set_error (error, POLKIT_ERROR, POLKIT_ERROR_NOT_SUPPORTED, "Cannot resolve SGLogin session for %s",
                   G_OBJECT_TYPE_NAME (subject));
      goto out;
    }
  pid = polkit_unix_process_get_pid (process);
  /* Never replace an existing subject's expected start time with a fresh one. */
  result = sgl_pid_get_session (monitor->client, pid, polkit_unix_process_get_start_time (process), &sid);
  if (result == 0 && pid == polkit_unix_process_get_pid (process))
    session = polkit_unix_session_new (sid);
  else if (result != -ENODATA && result != -ENOENT)
    provider_error (monitor, "process session", result == 0 ? -ESTALE : result, error);
out:
  sgl_free (sid);
  g_clear_object (&temporary);
  return session;
}
static gboolean
session_flag (PolkitBackendSessionMonitor *monitor, PolkitSubject *session, gboolean active)
{
  const gchar *sid = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session));
  int result = active ? sgl_session_is_active (monitor->client, sid) :
                        sgl_session_is_local (monitor->client, sid);
  if (result < 0)
    provider_error (monitor, active ? "session activity" : "session locality", result, NULL);
  return result > 0;
}
gboolean
polkit_backend_session_monitor_is_session_local (PolkitBackendSessionMonitor *monitor,
                                                 PolkitSubject *session)
{
  return session_flag (monitor, session, FALSE);
}
gboolean
polkit_backend_session_monitor_is_session_active (PolkitBackendSessionMonitor *monitor,
                                                  PolkitSubject *session)
{
  return session_flag (monitor, session, TRUE);
}
