/*
 * Isolated native SGLogin provider acceptance.
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
#include <string.h>
#include <unistd.h>
#include <polkit/polkit.h>
#include <polkitbackend/polkitbackend.h>
#include <polkitbackend/polkitbackendjsauthority.h>
#include <polkitbackend/polkitbackendsessionmonitor.h>

#define SID "0123456789abcdef0123456789abcdef"
#define OTHER_SID "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
static GDBusConnection *bus;
static guint changes;

static void
changed (PolkitBackendSessionMonitor *monitor, gpointer unused)
{
  (void) monitor;
  (void) unused;
  changes++;
}
static GVariant *
control (const gchar *method, GVariant *args)
{
  GError *error = NULL;
  GVariant *result = g_dbus_connection_call_sync (bus, "org.example.SGLoginTest", "/org/example/Test",
                                                "org.example.SGLoginTest", method, args, NULL,
                                                G_DBUS_CALL_FLAGS_NO_AUTO_START, 10000, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (result);
  return result;
}
static void
mode (const char *state)
{
  changes = 0;
  g_print ("fixture transition: %s\n", state);
  g_variant_unref (control ("SetState", g_variant_new ("(s)", state)));
}
static guint
queries (void)
{
  GVariant *result = control ("Queries", NULL);
  guint count;
  g_variant_get (result, "(u)", &count);
  g_variant_unref (result);
  return count;
}
static void
wait_changed (void)
{
  gint64 deadline = g_get_monotonic_time () + 2000000;
  while (changes == 0 && g_get_monotonic_time () < deadline)
    {
      while (g_main_context_iteration (NULL, FALSE));
      g_usleep (1000);
    }
  g_assert_cmpuint (changes, >, 0);
  changes = 0;
}
static void
assert_flags (PolkitBackendSessionMonitor *monitor, PolkitSubject *session,
              gboolean local, gboolean active)
{
  g_assert_cmpint (polkit_backend_session_monitor_is_session_local (monitor, session), ==, local);
  g_assert_cmpint (polkit_backend_session_monitor_is_session_active (monitor, session), ==, active);
}
static PolkitDetails *
expected_properties (gboolean local, gboolean active, const gchar *seat)
{
  PolkitDetails *details = polkit_details_new ();
  polkit_details_insert (details, "session", SID);
  polkit_details_insert (details, "seat", seat ? seat : "");
  polkit_details_insert (details, "local", local ? "true" : "false");
  polkit_details_insert (details, "active", active ? "true" : "false");
  return details;
}
static void
check_js (PolkitBackendInteractiveAuthority *authority, PolkitSubject *subject,
          gboolean local, gboolean active, const gchar *seat)
{
  PolkitIdentity *user = polkit_unix_user_new (getuid ());
  PolkitDetails *details = expected_properties (local, active, seat);
  PolkitImplicitAuthorization result;
  GList *admins;
  guint before = queries ();

  result = polkit_backend_interactive_authority_check_authorization_sync (authority, subject, subject,
             user, local, active, "org.example.sglogin.facts", details,
             POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED);
  g_assert_cmpint (result, ==, POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED);
  g_assert_cmpuint (queries (), >, before); /* JS independently resolves session/seat. */
  before = queries ();
  admins = polkit_backend_interactive_authority_get_admin_identities (authority, subject, subject,
             user, local, active, "org.example.sglogin.facts", details);
  g_assert_cmpuint (g_list_length (admins), ==, 1);
  g_assert_cmpint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (admins->data)), ==, 1000);
  g_assert_cmpuint (queries (), >, before);
  g_list_free_full (admins, g_object_unref);
  g_object_unref (details);
  g_object_unref (user);
}
typedef struct
{
  gboolean done;
  PolkitAuthorizationResult *result;
  GError *error;
} Check;
static void
check_done (GObject *object, GAsyncResult *result, gpointer data)
{
  Check *check = data;
  check->result = polkit_backend_authority_check_authorization_finish (
                    POLKIT_BACKEND_AUTHORITY (object), result, &check->error);
  check->done = TRUE;
}
static void
check_policy (PolkitBackendInteractiveAuthority *authority, PolkitSubject *subject,
              const gchar *action, gboolean local, gboolean active, const gchar *seat,
              gboolean authorized, gboolean challenge)
{
  Check check = {0};
  PolkitDetails *details;
  if (g_getenv ("POLKIT_SGLOGIN_FULL_POLICY") == NULL)
    return;
  details = expected_properties (local, active, seat);
  polkit_backend_authority_check_authorization (POLKIT_BACKEND_AUTHORITY (authority), subject, subject,
       action, details, POLKIT_CHECK_AUTHORIZATION_FLAGS_ALWAYS_CHECK, NULL, check_done, &check);
  while (!check.done)
    g_main_context_iteration (NULL, TRUE);
  g_assert_no_error (check.error);
  g_assert_nonnull (check.result);
  g_assert_cmpint (polkit_authorization_result_get_is_authorized (check.result), ==, authorized);
  g_assert_cmpint (polkit_authorization_result_get_is_challenge (check.result), ==, challenge);
  g_object_unref (check.result);
  g_object_unref (details);
}
/* Scripted agent protocol only: no installed PAM stack, account or secret. */
typedef struct
{
  PolkitBackendAuthority *authority;
  PolkitSubject *caller;
  GDBusMethodInvocation *pending;
  gboolean defer, change_metadata;
  guint begins, cancels;
} Agent;

static void
agent_method (GDBusConnection *connection, const gchar *sender, const gchar *path,
              const gchar *interface, const gchar *method, GVariant *parameters,
              GDBusMethodInvocation *invocation, gpointer data)
{
  Agent *agent = data;
  GError *error = NULL;
  (void) connection;
  (void) sender;
  (void) path;
  (void) interface;
  if (g_str_equal (method, "BeginAuthentication"))
    {
      GVariant *value = g_variant_get_child_value (parameters, 4);
      const gchar *cookie = g_variant_get_string (value, NULL);
      PolkitIdentity *wrong = polkit_unix_user_new (12345);
      PolkitIdentity *correct = polkit_unix_user_new (getuid ());
      agent->begins++;
      if (agent->defer)
        agent->pending = g_object_ref (invocation);
      else
        {
          g_assert_false (polkit_backend_authority_authentication_agent_response (
                            agent->authority, agent->caller, 1000, cookie, wrong, &error));
          g_assert_cmpstr (error->message, ==, "The authenticated identity is wrong");
          g_clear_error (&error);
          g_assert_false (polkit_backend_authority_authentication_agent_response (
                            agent->authority, agent->caller, 0, cookie, correct, &error));
          g_assert_cmpstr (error->message, ==, "No session for cookie");
          g_clear_error (&error);
          if (agent->change_metadata)
            mode ("no-context");
          g_assert_true (polkit_backend_authority_authentication_agent_response (
                           agent->authority, agent->caller, 1000, cookie, correct, &error));
          g_assert_no_error (error);
          g_dbus_method_invocation_return_value (invocation, NULL);
        }
      g_object_unref (wrong);
      g_object_unref (correct);
      g_variant_unref (value);
    }
  else
    {
      g_assert_cmpstr (method, ==, "CancelAuthentication");
      agent->cancels++;
      g_assert_nonnull (agent->pending);
      g_dbus_method_invocation_return_dbus_error (agent->pending,
                         "org.freedesktop.PolicyKit1.Error.Cancelled", "fixture cancellation");
      g_clear_object (&agent->pending);
      g_dbus_method_invocation_return_value (invocation, NULL);
    }
}

static gchar *
interactive_check (PolkitBackendInteractiveAuthority *authority, PolkitSubject *subject,
                   const gchar *action, Agent *agent)
{
  Check check = {0};
  GCancellable *cancel = g_cancellable_new ();
  PolkitDetails *details = polkit_details_new ();
  gchar *id = NULL;
  polkit_backend_authority_check_authorization (POLKIT_BACKEND_AUTHORITY (authority), agent->caller,
       subject, action, details, POLKIT_CHECK_AUTHORIZATION_FLAGS_ALWAYS_CHECK |
       POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION, cancel, check_done, &check);
  if (agent->defer)
    {
      while (agent->pending == NULL && !check.done)
        g_main_context_iteration (NULL, TRUE);
      g_assert_nonnull (agent->pending);
      g_cancellable_cancel (cancel);
    }
  while (!check.done)
    g_main_context_iteration (NULL, TRUE);
  if (agent->defer)
    {
      g_assert_true (check.error != NULL ||
                     !polkit_authorization_result_get_is_authorized (check.result));
      while (agent->pending != NULL)
        g_main_context_iteration (NULL, TRUE);
      g_assert_cmpuint (agent->cancels, >, 0);
    }
  else
    {
      g_assert_no_error (check.error);
      g_assert_true (polkit_authorization_result_get_is_authorized (check.result));
      id = g_strdup (polkit_authorization_result_get_temporary_authorization_id (check.result));
    }
  g_clear_object (&check.result);
  g_clear_error (&check.error);
  g_object_unref (cancel);
  g_object_unref (details);
  return id;
}

static void
check_agent_and_retention (PolkitBackendInteractiveAuthority *authority,
                           PolkitSubject *subject, PolkitSubject *session, PolkitSubject *caller)
{
  const gchar *xml = "<node><interface name='org.freedesktop.PolicyKit1.AuthenticationAgent'>"
    "<method name='BeginAuthentication'><arg type='s' direction='in'/>"
    "<arg type='s' direction='in'/><arg type='s' direction='in'/>"
    "<arg type='a{ss}' direction='in'/><arg type='s' direction='in'/>"
    "<arg type='a(sa{sv})' direction='in'/></method>"
    "<method name='CancelAuthentication'><arg type='s' direction='in'/></method>"
    "</interface></node>";
  const GDBusInterfaceVTable vtable = { .method_call = agent_method };
  Agent agent = { .authority = POLKIT_BACKEND_AUTHORITY (authority), .caller = caller };
  GError *error = NULL;
  GDBusNodeInfo *info;
  guint registration, before;
  gchar *id;
  gint64 deadline;
  if (g_getenv ("POLKIT_SGLOGIN_FULL_POLICY") == NULL)
    return;
  info = g_dbus_node_info_new_for_xml (xml, &error);
  g_assert_no_error (error);
  registration = g_dbus_connection_register_object (bus, "/org/example/Agent", info->interfaces[0],
                                                     &vtable, &agent, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (registration, >, 0);
  g_assert_true (polkit_backend_authority_register_authentication_agent (agent.authority,
                 caller, session, "C", "/org/example/Agent", NULL, &error));
  g_assert_no_error (error);
  /* Successful challenge completion retains upstream semantics even when
   * metadata changed during the challenge: no new policy reevaluation. */
  agent.change_metadata = TRUE;
  g_assert_null (interactive_check (authority, subject, "org.example.sglogin.challenge", &agent));
  agent.change_metadata = FALSE;
  mode ("active");
  polkit_backend_interactive_authority_set_expiration_seconds (authority, 1);
  id = interactive_check (authority, subject, "org.example.sglogin.keep", &agent);
  g_assert_nonnull (id);
  before = queries ();
  mode ("inactive");
  check_policy (authority, subject, "org.example.sglogin.keep", TRUE, FALSE, "seat0", TRUE, FALSE);
  g_assert_cmpuint (queries (), >, before); /* Normal provider/rule path still runs. */
  g_assert_cmpuint (agent.begins, ==, 2); /* Seat hints did not revoke the grant. */
  g_assert_true (polkit_backend_authority_revoke_temporary_authorization_by_id (
                   agent.authority, caller, id, &error));
  g_assert_no_error (error);
  g_free (id);
  check_policy (authority, subject, "org.example.sglogin.keep", TRUE, FALSE, "seat0", FALSE, TRUE);
  id = interactive_check (authority, subject, "org.example.sglogin.keep", &agent);
  g_assert_nonnull (id);
  g_free (id);
  deadline = g_get_monotonic_time () + 2200000;
  while (g_get_monotonic_time () < deadline)
    {
      while (g_main_context_iteration (NULL, FALSE));
      g_usleep (1000);
    }
  check_policy (authority, subject, "org.example.sglogin.keep", TRUE, FALSE, "seat0", FALSE, TRUE);
  agent.defer = TRUE;
  g_assert_null (interactive_check (authority, subject, "org.example.sglogin.challenge", &agent));
  g_assert_true (polkit_backend_authority_unregister_authentication_agent (agent.authority,
                  caller, session, "/org/example/Agent", &error));
  g_assert_no_error (error);
  g_dbus_connection_unregister_object (bus, registration);
  g_dbus_node_info_unref (info);
  mode ("active");
}

typedef struct { gboolean done; PolkitSubject *session; GError *error; } SessionInit;

static void
session_done (GObject *object, GAsyncResult *result, gpointer data)
{
  SessionInit *init = data;
  (void) object;
  init->session = polkit_unix_session_new_for_process_finish (result, &init->error);
  init->done = TRUE;
}

static void
check_session_construction (PolkitSubject *session, gboolean present)
{
  SessionInit init = {0};
  GError *error = NULL;
  PolkitSubject *parsed;
  gchar *serialized = polkit_subject_to_string (session);
  g_assert_cmpstr (serialized, ==, "unix-session:" SID);
  parsed = polkit_subject_from_string (serialized, &error);
  g_assert_no_error (error);
  g_assert_true (polkit_subject_equal (session, parsed));
  g_object_unref (parsed);
  g_free (serialized);
  polkit_unix_session_new_for_process (getpid (), NULL, session_done, &init);
  while (!init.done)
    g_main_context_iteration (NULL, TRUE);
  if (present)
    {
      g_assert_no_error (init.error);
      g_assert_nonnull (init.session);
      g_assert_true (polkit_subject_equal (session, init.session));
    }
  else
    {
      g_assert_nonnull (init.error);
      g_assert_null (init.session);
    }
  g_clear_object (&init.session);
  g_clear_error (&init.error);
}

typedef struct { gboolean done, exists; GError *error; } Exists;
static void
exists_done (GObject *object, GAsyncResult *result, gpointer data)
{
  Exists *exists = data;
  exists->exists = polkit_subject_exists_finish (POLKIT_SUBJECT (object), result, &exists->error);
  exists->done = TRUE;
}
typedef struct { gboolean done; GPermission *permission; GError *error; } Permission;

static void
permission_done (GObject *object, GAsyncResult *result, gpointer data)
{
  Permission *permission = data;
  (void) object;
  permission->permission = polkit_permission_new_finish (result, &permission->error);
  permission->done = TRUE;
}

static void
wait_allowed (GPermission *permission, gboolean expected)
{
  gint64 deadline = g_get_monotonic_time () + 5000000;
  while (g_permission_get_allowed (permission) != expected && g_get_monotonic_time () < deadline)
    {
      while (g_main_context_iteration (NULL, FALSE));
      g_usleep (1000);
    }
  g_assert_cmpint (g_permission_get_allowed (permission), ==, expected);
}

static int
unprivileged_client (void)
{
  GError *error = NULL;
  Permission permission = {0};
  PolkitBackendSessionMonitor *monitor;
  PolkitSubject *subject, *session, *resolved, *other;
  PolkitIdentity *user;
  PolkitAuthority *authority;
  gboolean matches = FALSE;
  g_assert_cmpint (getuid (), ==, 65534);
  bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  g_assert_no_error (error);
  monitor = polkit_backend_session_monitor_new ();
  subject = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());
  session = polkit_backend_session_monitor_get_session_for_subject (monitor, subject, &error);
  g_assert_no_error (error);
  g_assert_nonnull (session);
  assert_flags (monitor, session, TRUE, TRUE);
  user = polkit_backend_session_monitor_get_user_for_subject (monitor, subject, &matches, &error);
  g_assert_no_error (error);
  g_assert_true (matches);
  g_assert_cmpint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (user)), ==, getuid ());
  g_object_unref (user);
  g_assert_true (polkit_subject_exists_sync (session, NULL, &error));
  g_assert_no_error (error);
  resolved = polkit_unix_session_new_for_process_sync (getpid (), NULL, &error);
  g_assert_no_error (error);
  g_assert_true (polkit_subject_equal (session, resolved));
  g_object_unref (resolved);
  if (g_getenv ("POLKIT_SGLOGIN_FULL_POLICY") != NULL)
    {
      polkit_permission_new ("org.example.sglogin.implicit", NULL, NULL, permission_done, &permission);
      while (!permission.done)
        g_main_context_iteration (NULL, TRUE);
      g_assert_no_error (permission.error);
      g_assert_nonnull (permission.permission);
      g_assert_true (g_permission_get_allowed (permission.permission));
      mode ("inactive");
      wait_allowed (permission.permission, FALSE);
      mode ("active");
      wait_allowed (permission.permission, TRUE);
      g_object_unref (permission.permission);
      g_print ("Unprivileged PolkitPermission refresh acceptance passed\n");
    }
  /* Two valid sessions with the same owning UID are not interchangeable agent
   * scopes. The caller's actual process membership remains authoritative. */
  authority = polkit_authority_get_sync (NULL, &error);
  g_assert_no_error (error);
  other = polkit_unix_session_new (OTHER_SID);
  user = polkit_backend_session_monitor_get_user_for_subject (monitor, other, &matches, &error);
  g_assert_no_error (error);
  g_assert_cmpint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (user)), ==, 1000);
  g_object_unref (user);
  g_assert_false (polkit_authority_register_authentication_agent_sync (
                    authority, other, "C", "/org/example/OtherAgent", NULL, &error));
  g_assert_nonnull (strstr (error->message, "Passed session and the session the caller is in differs"));
  g_clear_error (&error);
  mode ("absent");
  g_assert_false (polkit_authority_register_authentication_agent_sync (
                    authority, session, "C", "/org/example/OtherAgent", NULL, &error));
  g_assert_nonnull (strstr (error->message, "Cannot determine session the caller is in"));
  g_clear_error (&error);
  mode ("active");
  g_object_unref (other);
  g_object_unref (authority);
  g_object_unref (session);
  g_object_unref (subject);
  g_object_unref (monitor);
  g_object_unref (bus);
  g_print ("Unprivileged provider/client and agent-scope rejection acceptance passed\n");
  return 0;
}

static void
check_unprivileged_client (PolkitBackendInteractiveAuthority *authority)
{
  GError *error = NULL;
  gpointer registration;
  GVariant *reply;
  gint status = -999;
  gint64 deadline = g_get_monotonic_time () + 15000000;
  registration = polkit_backend_authority_register (POLKIT_BACKEND_AUTHORITY (authority), bus,
                                  "/org/freedesktop/PolicyKit1/Authority", &error);
  g_assert_no_error (error);
  g_assert_nonnull (registration);
  reply = g_dbus_connection_call_sync (bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
              "org.freedesktop.DBus", "RequestName", g_variant_new ("(su)", "org.freedesktop.PolicyKit1", 4),
              NULL, G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);
  g_assert_no_error (error);
  g_variant_unref (reply);
  g_variant_unref (control ("StartClient", NULL));
  while (status == -999 && g_get_monotonic_time () < deadline)
    {
      while (g_main_context_iteration (NULL, FALSE));
      reply = control ("ClientStatus", NULL);
      g_variant_get (reply, "(i)", &status);
      g_variant_unref (reply);
      g_usleep (1000);
    }
  g_assert_cmpint (status, ==, 0);
  polkit_backend_authority_unregister (registration);
}

int
main (int argc, char **argv)
{
  PolkitBackendSessionMonitor *monitor;
  PolkitBackendInteractiveAuthority *authority;
  PolkitSubject *subject, *session, *stale, *caller, *resolved;
  PolkitIdentity *user;
  GError *error = NULL;
  gchar *rules[] = { SGLOGIN_RULES_DIR, NULL };
  Exists exists = {0};
  gboolean matches = FALSE;
  if (argc == 2 && g_str_equal (argv[1], "--client"))
    return unprivileged_client ();
  g_assert_cmpint (argc, ==, 1);
  g_assert_cmpint (getuid (), ==, 0);
  g_assert_nonnull (g_getenv ("DBUS_SYSTEM_BUS_ADDRESS"));
  bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  g_assert_no_error (error);
  g_variant_unref (control ("Queries", NULL)); /* Requires disposable fixture. */
  monitor = polkit_backend_session_monitor_new ();
  g_signal_connect (monitor, "changed", G_CALLBACK (changed), NULL);
  subject = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());
  authority = g_object_new (POLKIT_BACKEND_TYPE_JS_AUTHORITY, "rules-dirs", rules, NULL);
  session = polkit_backend_session_monitor_get_session_for_subject (monitor, subject, &error);
  g_assert_no_error (error);
  g_assert_nonnull (session);
  g_assert_cmpstr (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session)), ==, SID);
  assert_flags (monitor, session, TRUE, TRUE);
  check_session_construction (session, TRUE);
  check_js (authority, subject, TRUE, TRUE, "seat0");
  check_policy (authority, subject, "org.example.sglogin.implicit", TRUE, TRUE, "seat0", TRUE, FALSE);
  check_policy (authority, subject, "org.example.sglogin.facts", TRUE, TRUE, "seat0", TRUE, FALSE);
  /* As upstream, passed booleans are reused while JS session/seat is queried
   * later. A metadata change does not require an atomic shared result. */
  mode ("unseated");
  check_js (authority, subject, TRUE, TRUE, NULL);
  mode ("active");
  user = polkit_backend_session_monitor_get_user_for_subject (monitor, subject, &matches, &error);
  g_assert_no_error (error);
  g_assert_true (matches);
  g_assert_cmpint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (user)), ==, 0);
  g_object_unref (user);
  resolved = polkit_unix_session_new_for_process_sync (getpid (), NULL, &error);
  g_assert_no_error (error);
  g_assert_true (polkit_subject_equal (session, resolved));
  g_object_unref (resolved);
  user = polkit_backend_session_monitor_get_user_for_subject (monitor, session, &matches, &error);
  g_assert_no_error (error);
  g_assert_cmpint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (user)), ==, 1000);
  g_object_unref (user);
  stale = polkit_unix_process_new_for_owner (getpid (),
             polkit_unix_process_get_start_time (POLKIT_UNIX_PROCESS (subject)) + 1, getuid ());
  g_assert_null (polkit_backend_session_monitor_get_session_for_subject (monitor, stale, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
  g_object_unref (stale);
  wait_changed ();
  mode ("inactive");
  wait_changed ();
  assert_flags (monitor, session, TRUE, FALSE);
  check_js (authority, subject, TRUE, FALSE, "seat0");
  check_policy (authority, subject, "org.example.sglogin.implicit", TRUE, FALSE, "seat0", FALSE, TRUE);
  check_policy (authority, subject, "org.example.sglogin.facts", TRUE, FALSE, "seat0", TRUE, FALSE);
  mode ("no-context");
  assert_flags (monitor, session, FALSE, FALSE);
  check_js (authority, subject, FALSE, FALSE, NULL);
  check_policy (authority, subject, "org.example.sglogin.implicit", FALSE, FALSE, NULL, FALSE, FALSE);
  mode ("ambiguous");
  assert_flags (monitor, session, FALSE, FALSE); /* Negative C values are not true. */
  check_js (authority, subject, FALSE, FALSE, NULL);
  mode ("unseated");
  g_assert_true (polkit_subject_exists_sync (session, NULL, &error));
  g_assert_no_error (error);
  assert_flags (monitor, session, FALSE, FALSE);
  mode ("active");
  mode ("seat-restart");
  g_assert_false (polkit_backend_session_monitor_is_session_active (monitor, session));
  wait_changed ();
  assert_flags (monitor, session, TRUE, TRUE);
  mode ("session-restart");
  g_assert_null (polkit_backend_session_monitor_get_session_for_subject (monitor, subject, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
  wait_changed ();
  resolved = polkit_backend_session_monitor_get_session_for_subject (monitor, subject, &error);
  g_assert_no_error (error);
  g_assert_nonnull (resolved);
  g_object_unref (resolved);
  assert_flags (monitor, session, TRUE, TRUE);
  mode ("spoof-seat");
  wait_changed ();
  assert_flags (monitor, session, FALSE, FALSE);
  g_assert_true (polkit_subject_exists_sync (session, NULL, &error));
  g_assert_no_error (error);
  mode ("seat-restart");
  wait_changed ();
  assert_flags (monitor, session, TRUE, TRUE);
  caller = polkit_system_bus_name_new (g_dbus_connection_get_unique_name (bus));
  resolved = polkit_backend_session_monitor_get_session_for_subject (monitor, caller, &error);
  g_assert_no_error (error);
  g_assert_true (polkit_subject_equal (session, resolved));
  g_object_unref (resolved);
  check_agent_and_retention (authority, subject, session, caller);
  check_unprivileged_client (authority);
  g_assert_true (polkit_backend_authority_register_authentication_agent (
                   POLKIT_BACKEND_AUTHORITY (authority), caller, session,
                   "C", "/org/example/Agent", NULL, &error));
  g_assert_no_error (error);
  mode ("absent");
  wait_changed ();
  g_assert_false (polkit_subject_exists_sync (session, NULL, &error));
  g_assert_no_error (error);
  polkit_subject_exists (session, NULL, exists_done, &exists);
  while (!exists.done)
    g_main_context_iteration (NULL, TRUE);
  g_assert_no_error (exists.error);
  g_assert_false (exists.exists);
  check_session_construction (session, FALSE);
  g_assert_null (polkit_unix_session_new_for_process_sync (getpid (), NULL, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
  mode ("active");
  g_assert_false (polkit_backend_authority_unregister_authentication_agent (
                    POLKIT_BACKEND_AUTHORITY (authority), caller, session, "/org/example/Agent", &error));
  g_assert_nonnull (error);
  g_assert_cmpstr (error->message, ==, "No such agent registered");
  g_clear_error (&error);
  g_object_unref (caller);
  g_object_unref (session);
  g_object_unref (subject);
  g_object_unref (authority);
  g_object_unref (monitor);
  g_object_unref (bus);
  if (g_getenv ("POLKIT_SGLOGIN_FULL_POLICY") != NULL)
    g_print ("SGLogin full policy, agent/retention, permission and provider acceptance passed\n");
  else
    g_print ("SGLogin basic provider acceptance passed (full action-policy fixtures not enabled)\n");
  return 0;
}
